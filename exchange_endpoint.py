

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
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    log = Log(message=json.dumps(d))
    g.session.add(log)
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
        sig = content.get('sig')
        payload = content.get('payload')
        if check_sig(payload, sig):
            # TODO: Add the order to the database
            sender_pk = payload['sender_pk']
            receiver_pk = payload['receiver_pk']
            buy_currency = payload['buy_currency']
            sell_currency = payload['sell_currency']
            buy_amount = payload['buy_amount']
            sell_amount = payload['sell_amount']
            order = Order(
                sender_pk=sender_pk, 
                receiver_pk=receiver_pk, 
                buy_currency=buy_currency,
                sell_currency=sell_currency,
                buy_amount=buy_amount,
                sell_amount=sell_amount
            )
            g.session.add(order)
            g.session.commit()

            # TODO: Fill the order
            unfilled_orders = g.session.query(Order).filter(Order.filled==None).all()
            fill_order(order, unfilled_orders)

            return jsonify(True)
        else:
            # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful; Done
            log_message(payload)
            return jsonify( False )

        

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    order_list = []
    order_objects = g.session.query(Order).all()

    for order_obj in order_objects:
        order_dict = {}
        order_dict['sender_pk'] = order_obj.sender_pk
        order_dict['receiver_pk'] = order_obj.receiver_pk
        order_dict['buy_currency'] = order_obj.buy_currency
        order_dict['sell_currency'] = order_obj.sell_currency
        order_dict['buy_amount'] = order_obj.buy_amount
        order_dict['sell_amount'] = order_obj.sell_amount
        order_dict['signature'] = order_obj.signature
        order_list.append(order_dict)

    return json.dumps(order_list)

if __name__ == '__main__':
    app.run(port='5002')
