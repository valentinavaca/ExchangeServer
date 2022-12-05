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

def check_sig(payload,sig):
    pk = payload.get('pk')
    if payload.get('platform') == 'Ethereum':
        encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        return eth_account.Account.recover_message(encoded_msg, signature=sig) == pk
    else:
        return algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)

def fill_order(order,txes=[]):
    pass
  
def log_message(d):
    msg = json.dumps(d)

    # TODO: Add message to the Log table
    log = Log(message=msg)
    g.session.add(log)
    g.session.commit()
    return

""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
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
        
        # TODO: Add the order to the database
        
        # TODO: Fill the order
        
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
        sig = content.get('sig')
        payload = content.get('payload')

        if check_sig(payload, sig): # successfully verified
            # 2. Add the order to the table in the database
            sender_pk = payload['sender_pk']
            receiver_pk = payload['receiver_pk']
            buy_currency = payload['buy_currency']
            sell_currency = payload['sell_currency']
            buy_amount = payload['buy_amount']
            sell_amount = payload['sell_amount']
            tx_id = payload['tx_id']
            order = Order(
                sender_pk=sender_pk, 
                receiver_pk=receiver_pk, 
                buy_currency=buy_currency,
                sell_currency=sell_currency,
                buy_amount=buy_amount,
                sell_amount=sell_amount,
                tx_id = tx_id,
            )
            g.session.add(order)
            g.session.commit()
            # 3a. Check if the order is backed by a transaction equal to the sell_amount
            if sell_currency == 'Ethereum':
                tx = g.w3.eth.get_transaction(tx_id)
                assert tx.value == sell_amount
            elif sell_currency == 'Algorand':
                tx = g.icl.search_transactions(txid=tx_id)
                assert tx.amoutn == sell_amount
            else:
                pass
            if (tx.platform!=tx.order.sell_currency or 
                sell_amount!=tx.order.sell_amount or 
                sender_pk!=tx.order.sender_pk or 
                0):
                return jsonify(False)
            else:
                # 3b. Fill the order (as in Exchange Server II) if the order is valid
                pass
                # 4. Execute the transactions
                execute_txes(txes)
        
        else: # not verified
            log_message(payload)
            return jsonify(False)
     
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "receiver_pk" ]
    
    # Same as before
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
        order_dict['tx_id'] = order_obj.tx_id
        order_list.append(order_dict)
    return json.dumps(order_list)

if __name__ == '__main__':
    app.run(port='5002')
