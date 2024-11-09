from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import psycopg2
import logging
from datetime import datetime


app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost:5432/ecommerce'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database Connection 
try:
    conn = psycopg2.connect(
        dbname="ecommerce",
        user="postgres",
        password="123",
        host="localhost",
        port="5432"
    )
    cur = conn.cursor()
    print("Database connected successfully!")
except Exception as e:
    logging.error(f"Error connecting to the database: {e}")
    exit()  

# Models (SQLAlchemy ORM)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    address = db.Column(db.Text, nullable=True)
    orders = db.relationship('Order', backref='user', lazy=True)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    carts = db.relationship('Cart', backref='product', lazy=True)
    order_details = db.relationship('OrderDetail', backref='product', lazy=True)

class Cart(db.Model):
    __tablename__ = 'carts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    status = db.Column(db.String(50), default="Pending")  
    order_details = db.relationship('OrderDetail', backref='order', lazy=True)

class OrderDetail(db.Model):
    __tablename__ = 'order_details'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)



# Utility Functions
def validate_email(email):
    return '@' in email and '.' in email.split('@')[1]

def validate_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password)

@app.before_request
def log_request_info():
    print(f"Request URL: {request.url}")


# Routes for Authentication
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    address = data.get('address', None)
    
    if not validate_email(email):
        return jsonify({"message": "Invalid email format."}), 400
    if not validate_password(password):
        return jsonify({"message": "Password must be at least 8 characters long and contain a number."}), 400
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Email is already registered."}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password=hashed_password, address=address)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "Signup successful.", "user_id": new_user.id}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials."}), 400
    
    access_token = create_access_token(identity=user.id)
    return jsonify({"message": "Signin successful.", "access_token": access_token})

# Product Management Routes
@app.route('/addproduct', methods=['POST'])
@jwt_required()
def add_product():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    category = data.get('category')
    
    if not name or not description or not price or not category:
        return jsonify({"message": "Missing required fields."}), 400
    
    if price <= 0:
        return jsonify({"message": "Price must be positive."}), 400
    
    new_product = Product(name=name, description=description, price=price, category=category)
    db.session.add(new_product)
    db.session.commit()
    
    return jsonify({"message": "Product added successfully.", "product_id": new_product.id}), 201

# @app.route('/updateproduct/<int:product_id>', methods=['PUT'])
# @jwt_required()
# def update_product(product_id):
#     data = request.get_json()
#     product = Product.query.get(product_id)
    
#     if not product:
#         return jsonify({"message": "Product not found."}), 404



@app.route('/updateproduct/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    print(f"Received product_id: {product_id}")  # Log to debug
    data = request.get_json()
    product = Product.query.get(product_id)
    
    if not product:
        return jsonify({"message": "Product not found."}), 404

    if 'name' in data:
        product.name = data['name']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        if data['price'] <= 0:
            return jsonify({"message": "Price must be positive."}), 400
        product.price = data['price']
    if 'category' in data:
        product.category = data['category']
    
    db.session.commit()
    
    return jsonify({"message": "Product updated successfully."})

@app.route('/deleteproduct/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    product = Product.query.get(product_id)
    
    if not product:
        return jsonify({"message": "Product not found."}), 404
    
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({"message": "Product deleted successfully."})

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    
    if not products:
        return jsonify({"message": "No products found."}), 404
    
    product_list = []
    for product in products:
        product_list.append({
            "id": product.id,
            "name": product.name,
            "description": product.description,
            "price": str(product.price),  
            "category": product.category
        })
    
    return jsonify({"products": product_list})

# Cart Management Routes
@app.route('/cart/add', methods=['POST'])
@jwt_required()
def add_to_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity')
    
    if quantity <= 0:
        return jsonify({"message": "Quantity must be a positive integer."}), 400
    
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"message": "Product not found."}), 404
    
    user_id = get_jwt_identity()
    cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = Cart(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({"message": "Product added to cart."})

@app.route('/cart/update', methods=['PUT'])
@jwt_required()
def update_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity')
    
    if quantity < 0:
        return jsonify({"message": "Quantity must be a non-negative integer."}), 400
    
    cart_item = Cart.query.filter_by(user_id=get_jwt_identity(), product_id=product_id).first()
    if not cart_item:
        return jsonify({"message": "Product not found in cart."}), 404
    
    if quantity == 0:
        db.session.delete(cart_item)
    else:
        cart_item.quantity = quantity
    
    db.session.commit()
    return jsonify({"message": "Cart updated successfully."})

@app.route('/cart/delete', methods=['DELETE'])
@jwt_required()
def delete_from_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    
    cart_item = Cart.query.filter_by(user_id=get_jwt_identity(), product_id=product_id).first()
    
    if not cart_item:
        return jsonify({"message": "Product not found in cart."}), 404
    
    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({"message": "Product removed from cart."})

@app.route('/cart', methods=['GET'])
@jwt_required()
def get_cart():
    user_id = get_jwt_identity()
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    
    if not cart_items:
        return jsonify({"message": "Cart is empty."}), 404
    
    cart_details = []
    total_amount = 0
    for item in cart_items:
        product = Product.query.get(item.product_id)
        item_total = item.quantity * product.price
        total_amount += item_total
        cart_details.append({
            "product_name": product.name,
            "description": product.description,
            "quantity": item.quantity,
            "price": product.price,
            "total": item_total
        })
    
    return jsonify({"cart": cart_details, "total_amount": total_amount})

@app.route('/placeorder', methods=['POST'])
@jwt_required()
def place_order():
    data = request.get_json()
    shipping_address = data.get('shipping_address')
    
    if not shipping_address:
        return jsonify({"message": "Shipping address is required."}), 400
    
    user_id = get_jwt_identity()
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    
    if not cart_items:
        return jsonify({"message": "Cart is empty."}), 400
    
    total_amount = 0
    for item in cart_items:
        product = Product.query.get(item.product_id)
        total_amount += item.quantity * product.price
    
    new_order = Order(user_id=user_id, shipping_address=shipping_address, total_amount=total_amount)
    db.session.add(new_order)
    db.session.commit()
    
    for item in cart_items:
        product = Product.query.get(item.product_id)
        order_detail = OrderDetail(order_id=new_order.id, product_id=product.id, quantity=item.quantity, price=product.price)
        db.session.add(order_detail)
    
    
    for item in cart_items:
        db.session.delete(item)  
    
    db.session.commit()
    
    return jsonify({"message": "Order placed successfully.", "order_id": new_order.id})




@app.route('/getallorders', methods=['GET'])
@jwt_required()
def get_all_orders():
    orders = Order.query.all()
    if not orders:
        return jsonify({"message": "No orders found."}), 404
    
    orders_data = []
    for order in orders:
        order_info = {
            "order_id": order.id,
            "user_id": order.user_id,
            "shipping_address": order.shipping_address,
            "status": order.status,
            "products": [{"product_name": p.product.name, "quantity": p.quantity} for p in order.order_details]
        }
        orders_data.append(order_info)
    
    return jsonify({"orders": orders_data})

@app.route('/orders/customer/<int:customer_id>', methods=['GET'])
@jwt_required()
def get_orders_by_customer(customer_id):
    orders = Order.query.filter_by(user_id=customer_id).all()
    if not orders:
        return jsonify({"message": "No orders found for this customer."}), 404
    
    orders_data = []
    for order in orders:
        order_info = {
            "order_id": order.id,
            "shipping_address": order.shipping_address,
            "status": order.status,
            "products": [{"product_name": p.product.name, "quantity": p.quantity} for p in order.order_details]
        }
        orders_data.append(order_info)
    
    return jsonify({"orders": orders_data})

if __name__ == '__main__':
    with app.app_context():  
        db.create_all()  
    app.run(debug=True, port=5000)

