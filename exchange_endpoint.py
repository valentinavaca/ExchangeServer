

from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

def check_sig(payload, sig):
    pk = payload.get('pk')
    if payload.get('platform') == 'Ethereum':
        encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        return eth_account.Account.recover_message(encoded_msg, signature=sig) == pk
    else:
        return algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)

def fill_order(order, txes=[]):
    for unfilled_order in txes:
        if find_match(order, unfilled_order):
            order.filled = datetime.now()
            unfilled_order.filled = datetime.now()
            order.counterparty_id = unfilled_order.id
            unfilled_order.counterparty_id = order.id
            g.session.commit()
            if order.buy_amount > unfilled_order.sell_amount:
                sender_pk = order.sender_pk
                receiver_pk = order.receiver_pk
                buy_currency = order.buy_currency
                sell_currency = order.sell_currency
                buy_amount = order.buy_amount - unfilled_order.sell_amount
                sell_amount = 1.1*(buy_amount * order.sell_amount/order.buy_amount )
                creator_id = order.id
                new_order = Order(
                    sender_pk = sender_pk, 
                    receiver_pk = receiver_pk, 
                    buy_currency = buy_currency,
                    sell_currency = sell_currency,
                    buy_amount = buy_amount,
                    sell_amount = sell_amount,
                    creator_id = creator_id,
                )
                unfilled_orders = g.session.query(Order).filter(Order.filled==None).all()
                fill_order(new_order, unfilled_orders)
                break
            if unfilled_order.sell_amount > order.buy_amount:
                sender_pk = unfilled_order.sender_pk
                receiver_pk = unfilled_order.receiver_pk
                buy_currency = unfilled_order.buy_currency
                sell_currency = unfilled_order.sell_currency
                sell_amount = unfilled_order.sell_amount - order.buy_amount
                buy_amount = 0.9 * ( sell_amount * unfilled_order.buy_amount / unfilled_order.sell_amount )
                creator_id = unfilled_order.id
                new_order = Order(
                    sender_pk = sender_pk, 
                    receiver_pk = receiver_pk, 
                    buy_currency = buy_currency,
                    sell_currency = sell_currency,
                    buy_amount = buy_amount,
                    sell_amount = sell_amount,
                    creator_id = creator_id,
                )
                unfilled_orders = g.session.query(Order).filter(Order.filled==None).all()
                fill_order(new_order, unfilled_orders)
                break
            break
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    payload = d.get("payload")
    msg = json.dumps(payload)
    log_obj = Log(message=msg)
    g.session.add(log_obj)
    g.session.commit()


def find_match(order, unfilled_order):
    if order.filled==None:
        if order.buy_currency == unfilled_order.sell_currency:
            if order.sell_currency == unfilled_order.buy_currency:
                if unfilled_order.sell_amount / unfilled_order.buy_amount >= order.buy_amount / order.sell_amount:
                    return True
    return False
""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        payload = content["payload"]
        platform = payload.get("platform")
        sender_pk = payload.get("sender_pk")
        sig = content.get("sig")
        

        if platform == "Ethereum":
            eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
            if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == sender_pk:
                response = True
        else:
            if algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, sender_pk):
                response = True

        if response:
            order_dict = {
                'buy_currency':payload["buy_currency"],
                'sell_currency':payload["sell_currency"]
                'buy_amount':payload["buy_amount"]
                'sell_amount':payload["sell_amount"]
                'sender_pk':payload["sender_pk"]
                'receiver_pk':payload["receiver_pk"]
            }
            process_order(order_dict)
            return jsonify(True)
        else:
            log_message(content)
            return jsonify(False)

        

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    orders = g.session.query(Order).all()
    order_data = []
    
    for order in orders:
        order_dict = {}
        sender_pk = order.sender_pk
        receiver_pk = order.receiver_pk
        buy_currency = order.buy_currency
        sell_currency = order.sell_currency
        buy_amount = order.buy_amount
        sell_amount = order.sell_amount
        sig = order.signature
        order_dict['sender_pk'] = sender_pk
        order_dict['receiver_pk'] = receiver_pk
        order_dict['buy_currency'] = buy_currency
        order_dict['sell_currency'] = sell_currency
        order_dict['buy_amount'] = buy_amount
        order_dict['sell_amount'] = sell_amount
        order_dict['signature'] = sig
        order_data.append(order_dict)
    output = {}
    output['data'] = order_data

    return jsonify(output)

def process_order(order_dict):
    buy_currency = order_dict['buy_currency']
    sell_currency = order_dict['sell_currency']
    buy_amount = order_dict['buy_amount']
    sell_amount = order_dict['sell_amount']
    sender_pk = order_dict['sender_pk']
    receiver_pk = order_dict['receiver_pk']
    
    if order_dict.get('creator_id') == None:
        order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount)    
    else:
        creator_id = order_dict.get('creator_id')
        order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, creator_id=creator_id)
    
    session.add(order)
    session.commit()
    
    orders = session.query(Order).filter(Order.filled == None).all()

    for curr_order in orders:
        if match_check(order, curr_order):
            order.filled = datetime.now()
            curr_order.filled = datetime.now()
            
            order.counterparty_id = curr_order.id
            curr_order.counterparty_id = order.id
            
            session.commit()
            
            child = {}
            if curr_order.sell_amount < order.buy_amount:
                child['buy_currency'] = order.buy_currency
                child['sell_currency'] = order.sell_currency
                child['sender_pk'] = order.sender_pk
                child['receiver_pk'] = order.receiver_pk
                child['creator_id'] = order.id
                child['buy_amount'] = order.buy_amount - curr_order.sell_amount
                child['sell_amount'] = ((order.buy_amount - curr_order.sell_amount) * order.sell_amount / order.buy_amount) * 1.1
                
                #loop
                process_order(child)
                
            if order.buy_amount < curr_order.sell_amount:
                child['buy_currency'] = curr_order.buy_currency
                child['sell_currency'] = curr_order.sell_currency
                child['sender_pk'] = curr_order.sender_pk
                child['receiver_pk'] = curr_order.receiver_pk
                child['creator_id'] = curr_order.id
                child['sell_amount'] = curr_order.sell_amount - order.buy_amount
                child['buy_amount'] = ((curr_order.sell_amount - order.buy_amount) * curr_order.buy_amount / curr_order.sell_amount) * 0.9
                
                #loop
                process_order(child)


if __name__ == '__main__':
    app.run(port='5002')
