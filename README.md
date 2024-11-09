Create a database in PostgreSQL. ( Ecommerce )
Restore the SQL file into the database.
Open the command prompt in the project folder directory.
Create Virtual Enviroment - python -m venv venv
Activate the virtual environment with - venv\Scripts\activate.
Install the required dependencies using - pip install -r requirements.txt.
Run the Python application with - python app.py.
And refer to the Screenshots folder 

now on postman

1. Sign Up User - http://localhost:5000/signup (POST)
    Body, raw, JSON:
{
    "name": "Goyam Nahar Jain",
    "email": "jaingoyamnahar@gmail.com",
    "password": "Goyam@12345",
    "address": "438, Clerk Colony"
} 


2. Sign in user - http://localhost:5000/signin   (POST)
    Body, raw, JSON:  
{
    "email": "jaingoyamnahar@gmail.com",
    "password": "Goyam@12345"
}

Copy access_token from the output 


3. Add Product - http://localhost:5000/addproduct (POST)
    Header: 
    Key: Authorization     
    Value: Bearer (access-token)

    Body, raw, JSON: 

{
    "name": "Mobile",
    "description": "Best Quality",
    "price": 15000,
    "category": "Electronics"
}


4. Update Product - http://localhost:5000/updateproduct/1 ( PUT )
    Headers: Add the Authorization header with the JWT token.  

{
  "name": "Updated Mobile",
  "price": 12000
}


5. Delete Product - http://localhost:5000/deleteproduct/1 ( DELETE )
    Headers: Add the Authorization header with the JWT token.  


6. Get All Products - http://localhost:5000/products (GET)
    Headers: Add the Authorization header with the JWT token.  


7. Add to Cart - http://localhost:5000/cart/add (POST)
    Headers: Add the Authorization header with the JWT token.
    Body, raw, JSON: 

{
    "product_id": 1,
    "quantity": 2
}


8. Update Cart - http://localhost:5000/cart/update ( PUT )
    Headers: Add the Authorization header with the JWT token.
    Body, raw, JSON: 

{
  "product_id": 1,
  "quantity": 3
}


9. Delete Product from Cart - http://localhost:5000/cart/delete ( DELETE )
    Headers: Add the Authorization header with the JWT token.
    Body, raw, JSON: 
{
  "product_id": 2   
}


10. Get Cart - http://localhost:5000/cart (GET)
    Headers: Add the Authorization header with the JWT token.


11. Place Order - http://localhost:5000/placeorder (POST)
    Headers: Add the Authorization header with the JWT token.
    Body, raw, JSON: 

{
    "shipping_address": "438, Clerk, Colony, Indore ( 9407529992 )"
}


12. Get All Orders http://localhost:5000/getallorders ( GET )
    Headers: Add the Authorization header with the JWT token.


13. Get Orders by Customer ID - http://localhost:5000/orders/customer/{customerId} ( GET ) 
    Headers: Add the Authorization header with the JWT token.





And if you face any error or if any API is not working, just contact me. I can solve the error

Goyam Nahar Jain
Email: jaingoyamnahar@gmail.com
LinkedIn: https://www.linkedin.com/in/goyam-nahar-jain-019608275/
