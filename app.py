from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import  generate_password_hash,check_password_hash
app=Flask(__name__)


app.config['SECRET_KEY']='thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////fdb.db'
db = SQLAlchemy(app)






class user(db.Model):
    id=db.Column(db.INTEGER,primary_key=True)
    public_id=db.Column(db.String(10),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)


class todo(db.Model):
    id=db.Column(db.INTEGER,primary_key=True)
    text=db.Column(db.String(60))
    complete = db.Column(db.Boolean)
    user_id=db.Column(db.INTEGER)





@app.route('/user',methods=['GET'])
def get_all_user():
    return jsonify({'message':'db sakhte shod'})



@app.route('/user/<user_id>',methods=['GET'])
def get_one_user():
    return ''

@app.route('/user',methods=['POST'])
def create_user():
    data=request.get_json()
    hashed_password=generate_password_hash(data['password'], method='sha256')
    new_user=user(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()
    users = user.query.all()
    print(users)


    return jsonify({'Message':'New user created' })


@app.route('/user/<user_id>',methods=['PUT'])
def promote_user():
    return ''

@app.route('/user/<user_id>',methods=['DELETE'])
def delete_user():
    return ''



if __name__=='__main__':
    app.run(debug=True)


