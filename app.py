import os
import logging
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint, google
from config import Config
from models import db, User, Plan

# Configuración de logs
logging.basicConfig(level=logging.INFO)

# Inicialización de la aplicación Flask
app = Flask(__name__)
app.config.from_object(Config)

# Extensiones
csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Blueprint de Google OAuth
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID", "TU_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "TU_CLIENT_SECRET"),
    redirect_url="/login/google/authorized",
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# Función que carga usuarios
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta principal
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Por favor ingrese ambos campos', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Usuario o contraseña incorrectos', 'error')
            return redirect(url_for('login'))

        login_user(user)
        flash(f'Bienvenido, {user.name}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Logs adicionales
        logging.info(f"Datos del formulario: name={name}, username={username}, email={email}, password={password}")

        if not name or not username or not email or not password:
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('El usuario o correo ya está registrado', 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(
                name=name,
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )

            # Logs adicionales
            logging.info(f"Objeto User creado: {new_user}")

            db.session.add(new_user)
            db.session.commit()
            logging.info(f"Usuario registrado: {username}, {email}")
            login_user(new_user)
            flash(f'¡Bienvenido {name}!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logging.error(f"Error al registrar usuario: {e}")
            flash(f'Error al registrar usuario: {e}', 'error')
            db.session.rollback()
            return redirect(url_for('register'))

    return render_template('register.html')

# Ruta de login con Google
@app.route('/login/google/authorized')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()

    email = user_info.get("email")
    name = user_info.get("name") or "Usuario"
    username = email.split("@")[0]

    user = User.query.filter_by(email=email).first()
    if not user:
        try:
            user = User(
                name=name,
                username=username,
                email=email,
                password_hash=generate_password_hash("oauth_dummy_password")
            )
            db.session.add(user)
            db.session.commit()
            logging.info(f"Usuario registrado con Google: {username}, {email}")
        except Exception as e:
            logging.error(f"Error al registrar usuario con Google: {e}")
            flash(f"Error al registrar usuario con Google: {e}", 'error')
            return redirect(url_for('login'))

    login_user(user)
    flash(f'Bienvenido {name} (Google)', 'success')
    return redirect(url_for('dashboard'))

# Ruta del dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name, username=current_user.username)

# Ruta de logout
@app.route('/logout')
@login_required
def logout():
    name = current_user.name
    logout_user()
    flash(f'{name}, has cerrado sesión correctamente', 'info')
    return redirect(url_for('login'))

# Ruta para favicon
@app.route('/favicon.ico')
def favicon():
    return '', 404

# Ruta para manejar el chat IA (simulado)
@app.route('/chat', methods=['POST'])
@login_required
@csrf.exempt
def chat():
    data = request.get_json()
    user_message = data.get('message', '')

    if "hola" in user_message.lower():
        response = "¡Hola! ¿En qué puedo ayudarte hoy?"
    elif "gracias" in user_message.lower():
        response = "¡De nada! Estoy aquí para ayudarte. "
    else:
        response = f"Recibí tu mensaje: '{user_message}', pero aún estoy aprendiendo "

    return jsonify({'response': response})

# Rutas para el carrito de compras
@app.route('/plans')
@login_required
def plans():
    plans = Plan.query.all()
    return render_template('plans.html', plans=plans)

@app.route('/add_to_cart/<int:plan_id>', methods=['POST'])
@login_required
def add_to_cart(plan_id):
    plan = Plan.query.get(plan_id)
    if plan:
        if 'cart' not in session:
            session['cart'] = []
        session['cart'].append(plan_id)
        session.modified = True
        flash(f'{plan.name} agregado al carrito', 'success')
    return redirect(url_for('plans'))

@app.route('/cart')
@login_required
def cart():
    logging.info("Accediendo a la ruta /cart")
    cart_items = []
    total = 0
    if 'cart' in session:
        logging.info(f"Contenido del carrito en la sesión: {session['cart']}")
        for plan_id in session['cart']:
            plan = Plan.query.get(plan_id)
            if plan:
                logging.info(f"Plan encontrado: {plan}")
                cart_items.append(plan)
                total += plan.price
            else:
                logging.warning(f"Plan con ID {plan_id} no encontrado")
    logging.info(f"Artículos en el carrito: {cart_items}")
    logging.info(f"Total del carrito: {total}")
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/remove_from_cart/<int:plan_id>', methods=['POST'])
@login_required
def remove_from_cart(plan_id):
    if 'cart' in session:
        if plan_id in session['cart']:
            session['cart'].remove(plan_id)
            session.modified = True
            flash('Plan eliminado del carrito', 'info')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    # Lógica para procesar el pago (integración con pasarela de pago)
    # ...
    session['cart'] = []
    session.modified = True
    flash('Pago realizado con éxito', 'success')
    return redirect(url_for('dashboard'))

# Punto de entrada principal
if __name__ == '__main__':
    app.run(debug=True)