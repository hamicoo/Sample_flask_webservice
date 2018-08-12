from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import  generate_password_hash,check_password_hash
import datetime
import jwt
from functools import wraps






app=Flask(__name__)
app.config['SECRET_KEY']='hamedazizi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:123@localhost/flask'
db = SQLAlchemy(app)
result = db.engine.execute('set timezone="iran"')




class User(db.Model):
    id=db.Column(db.INT,primary_key=True)
    public_id=db.Column(db.String(100),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    create_date=db.Column(db.TIMESTAMP)
    last_edit_date=db.Column(db.TIMESTAMP)
    admin=db.Column(db.Boolean)



class Todo(db.Model):
    id=db.Column(db.INT,primary_key=True)
    text=db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    user_id=db.Column(db.INT)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'Error': 'Token Not Found'})
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])

            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return  jsonify({'Token': 'Token Is Invalid !'}),401

        return f(current_user,*args,**kwargs)

    return decorated






@app.route('/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify this user',401,{'www-authenticate':'basic_realm="login required !"'})

    user=User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify this user', 401, {'www-authenticate': 'basic_realm="login required !"'})

    if check_password_hash(user.password,auth.password):
        token=jwt.encode({'public_id':user.public_id,'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})

    return make_response('could not verify this user', 401, {'www-authenticate': 'basic_realm="login required !"'})






@app.route('/user',methods=['GET'])
@token_required


def get_all_user(current_user):
    print(current_user.name)
    print(current_user.admin)
    if not current_user.admin:
        return jsonify({'Error': 'cannot perform that function *'})
    users=User.query.all()
    output=[]

    for user in users:
        dic={}
        dic['public_id']=user.public_id
        dic['user_name']=user.name
        dic['password']=user.password
        dic['admin_status']=user.admin
        dic['create_date']=user.create_date
        dic['last_edit_date']=user.last_edit_date
        output.append(dic)
    return jsonify({'users': output})




@app.route('/user/<public_id>',methods=['GET'])
@token_required

def get_one_user(current_user,public_id):
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Status':'User not found'})
    dic={}
    dic['public_id'] = user.public_id
    dic['user_name'] = user.name
    dic['password'] = user.password
    dic['admin_status'] = user.admin
    dic['create_date'] = user.create_date
    dic['last_edit_date']=user.last_edit_date
    return jsonify({'user': dic})




@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
    data=request.get_json()
    dt=datetime.datetime.now()
    hashed_password=generate_password_hash(data['password'], method='sha256')
    new_user= User(public_id=str(uuid.uuid4()),name=data['name'], password=str(hashed_password),admin=False,create_date=dt)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message':'New user created'})


@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id,admin=False).first()
    if not user:
        return jsonify({'status': 'not found'})
    user.admin=True
    db.session.commit()
    return jsonify({'status':'success','description':'user ' +str(user.name) + ' changed to admin'})


@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Status': 'User not found'})

    db.session.delete(user)
    db.session.commit()
    return jsonify ({'status':'success','description':'user ' +str(user.name) + ' Has Been Deleted'})


if __name__=='__main__':
    app.run(debug=True)


