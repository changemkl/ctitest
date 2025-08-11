from flask import Flask, redirect, url_for
from flask_login import LoginManager
from .auth.routes import auth_bp
from .threats.routes import threat_bp
from .database.mongo import get_user_by_id


app = Flask(__name__)
app.secret_key = 'your-secret-key'



login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

app.register_blueprint(auth_bp)
app.register_blueprint(threat_bp)

@app.route('/')
def index():
    return redirect(url_for('threat.view_threats'))

if __name__ == '__main__':
    app.run(debug=True)
