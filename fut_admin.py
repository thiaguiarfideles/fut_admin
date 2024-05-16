import logging
import random
import smtplib
import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_mail import Mail, Message
from functools import wraps
from itertools import count

import bcrypt
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    send_from_directory,
    current_app,
)
import os
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_migrate import Migrate

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey, func
from sqlalchemy.orm import relationship
from utils import generate_random_token
from wtforms import (
    DateField,
    FileField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    ValidationError,
    validators,
)
from wtforms.validators import DataRequired, Email, Length

app = Flask(__name__)

app.config["SECRET_KEY"] = "uaie4q*(eo7ms*8vl_mde6x+a(&vx8nphm2o5n^=h0=p^3@u2"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///football.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Configurações do servidor de e-mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'seumkt@gmail.com'
app.config['MAIL_PASSWORD'] = 'utjpnvnrziovcstz'
app.config['MAIL_DEFAULT_SENDER'] = 'seumkt@gmail.com'
app.config["SENDER_EMAIL"] = "seumkt@gmail.com"

mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
bcrypt = Bcrypt(app)
# Configurando o diretório dos templates
app.config[
    "TEMPLATES_AUTO_RELOAD"
] = True  # Isso permite recarregar automaticamente os templates quando forem modificados
app.template_folder = (
    "templates"  # Defina o diretório onde seus templates estão armazenados
)

# Caminho para a pasta 'static'
STATIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Caminho para a pasta 'media'
MEDIA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "media")


# Desativar logs de solicitações de arquivos estáticos
#log = logging.getLogger('werkzeug')
#log.setLevel(logging.ERROR)



# Configurações do servidor de e-mail
EMAIL_FROM = "seumkt@gmail.com"  # email de origem
EMAIL_TO = ""  # email de destino
SENHA = "utjpnvnrziovcstz"


class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_grupo = db.Column(db.String(50), nullable=False)


class users(db.Model, UserMixin):

    __tablename__ = "users"

    id_usuario = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    email = db.Column(db.String, unique=True, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_expiration = db.Column(db.DateTime, nullable=True)
    current_password = db.Column(db.String(500), nullable=True)
    new_password = db.Column(db.String(500), nullable=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupo.id"))
    free_access_expiration = db.Column(db.DateTime, nullable=True)
    access_expiry_date = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, username, password, full_name, date_of_birth, email, admin, grupo_id, registered_on, access_expiry_date=None):
        self.username = username
        self.password = password
        self.full_name = full_name
        self.date_of_birth = date_of_birth
        self.email = email
        self.admin = admin
        self.grupo_id = grupo_id
        self.registered_on = registered_on
        self.access_expiry_date = access_expiry_date  # Inicializa o novo campo

    def __repr__(self):
        return f"<users {self.username}>"

    def is_user_approved(self):
        """Check if the user is approved."""
        return self.is_approved

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.is_approved

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def is_active(self):
        """Return True if the user is active."""
        return True  # You can modify this logic based on your requirement

    
        # Método para verificar se o acesso gratuito expirou
    def is_free_access_expired(self):
        if self.free_access_expiration is None:
            return False
        return self.free_access_expiration <= datetime.utcnow()
    
        # Método para definir a data de expiração do acesso gratuito
    def set_free_access_expiration(self):
        self.free_access_expiration = datetime.utcnow() + timedelta(days=30)
        db.session.commit()
        
    def is_access_expired(self):
        """Check if the user's access has expired."""
        if not self.access_expiry_date:
            # Se a data de expiração do acesso não estiver definida, o acesso não expirou
            return False
        return datetime.now() > self.access_expiry_date    


# hashed_password = bcrypt.generate_password_hash(users.password).decode('utf-8')


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=50)])
    password = PasswordField("Password", validators=[DataRequired()])


class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Enviar Email de Redefinição')


class PasswordEditForm(FlaskForm):
    current_password = PasswordField(
        "Senha Atual", validators=[validators.DataRequired()]
    )
    new_password = PasswordField(
        "Nova Senha",
        validators=[
            validators.DataRequired(),
            validators.EqualTo("confirm_password", message="Senhas devem ser iguais"),
        ],
    )
    confirm_password = PasswordField(
        "Confirme a Nova Senha", validators=[validators.DataRequired()]
    )
    submit = SubmitField("Alterar Senha")


class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupo.id"))
    grupo = db.relationship("Grupo", backref=db.backref("jogadores", lazy=True))
    status = db.Column(db.String(10), nullable=False, info={"verbose_name": "Status"})
    payment = db.Column(
        db.String(3), nullable=False, info={"verbose_name": "Pagamento"}
    )
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )

    score = relationship("Score", back_populates="player")
    artilheiros = db.relationship("Artilheiro", back_populates="player")


class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey("player.id"), nullable=False)
    preferencia_pe = db.Column(db.String(10), nullable=False)
    posicao = db.Column(db.String(20), nullable=False)
    nota = db.Column(db.Integer, nullable=False)

    player = relationship("Player", back_populates="score")


class Artilheiro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey("player.id"), nullable=False)
    data_partida = db.Column(db.DateTime, nullable=False)
    num_gols = db.Column(db.Integer, nullable=False)

    player = relationship("Player", back_populates="artilheiros")


class DiaFut(db.Model):
    id_partida = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dt_jogo = db.Column(db.DateTime, nullable=False)
    dt_confirmacao = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )
    dt_encerramento = db.Column(db.DateTime, nullable=True)
    loca_partida = db.Column(db.String(100), nullable=False)
    ativo = db.Column(db.Boolean, nullable=False, default=True)


class PartidaJogador(db.Model):
    __tablename__ = "partida_jogador"
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey("player.id"), nullable=False)
    player = db.relationship(
        "Player", foreign_keys=[player_id], backref=db.backref("partidas", lazy=True)
    )
    id_partida = db.Column(
        db.Integer, db.ForeignKey("dia_fut.id_partida"), nullable=False
    )
    presenca = db.Column(db.String(3), nullable=False, default="no")
    artilheiro_id = db.Column(db.Integer, db.ForeignKey("player.id"))
    artilheiro = db.relationship("Player", foreign_keys=[artilheiro_id])

    dt_confirmacao = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )  # Add the dt_confirmacao property here

    __table_args__ = (
        db.ForeignKeyConstraint(
            ["id_partida"], ["dia_fut.id_partida"], name="fk_partida_jogador_id_partida"
        ),
    )


import random

#def create_admin():
#    """Creates the admin user."""
 #   db.session.add(User(
  #      email="ad@min.com",
   #     password="admin",
    #    admin=True,
     #   confirmed=True,
      #  confirmed_on=datetime.datetime.now())
    #)
    #db.session.commit()

class User(UserMixin):
    def __init__(self, id):
        self.id = id

    

@app.route("/send_mail/<int:user_id>")
def send_mail(user_id):
    # Consultar o banco de dados para obter o e-mail do usuário
    user = users.query.get(user_id)
    if user:
        recipient_email = user.email
        msg = Message("Olá", sender="seumkt@gmail.com", recipients=[recipient_email])
        msg.body = "Seja bem-vindo ao LigaAdmin!"
        mail.send(msg)
        return "Email enviado para " + recipient_email
    else:
        return "Usuário não encontrado"       


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/explorar")
@login_required
def explorar():
    return render_template("explorar.html")


@login_manager.user_loader
def user_loader(user_id):
    # Retrieve the user from the database using the username
    user = users.query.filter_by(username=user_id).first()
    return user


def send_approval_notification(user_email, pending_users):
    sender_email = "seumkt@gmail.com"
    subject = "Novos Registros Pendentes de aprovação"
    aprova_url = url_for("pendente_aprovacao")
    
    pending_users = users.query.filter_by(is_approved=False).all()
    
    # Construir a lista de nomes de usuário pendentes de aprovação
    pending_user_names = "\n".join([user.username for user in pending_users])

    body = f"""Prezado administrador,

Existem novos registros pendentes de aprovação. Por favor, revise-os.

Usuários pendentes de aprovação:
{pending_user_names}

Por favor, visite o seguinte link para mais detalhes:
{aprova_url}

Com os melhores cumprimentos,
O Administrador"""

    msg = Message(subject, sender=sender_email, recipients=[user_email])
    msg.body = body

    try:
        print(f"Enviando email para o administrador {user_email}")
        mail.send(msg)
        print("Email enviado com sucesso!")
    except Exception as e:
        print("Erro ao enviar email:", e)


        
# Route for user registration
# Rota para registro de jogadores
@app.route("/register", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        print("Form Data:", request.form)
        username = request.form["username"]
        password = request.form["password"]
        full_name = request.form["full_name"]
        date_of_birth = datetime.strptime(request.form["date_of_birth"], "%Y-%m-%d").date()
        email = request.form["email"]
        admin = request.form.get("admin") == "True"
        grupo_id = request.form["grupo"]

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Set registration timestamp
        registered_on = datetime.utcnow()
        
        # Definir a data de expiração do acesso para 30 dias a partir da data de registro
        access_expiry_date = datetime.utcnow() + timedelta(days=30)
        
        pending_users = users.query.filter_by(is_approved=False).all()
        print("New pending_users:", pending_users)
        
        sender_email = current_app.config.get("SENDER_EMAIL")
        print("novo send_approval_notification:", sender_email)

        # Create a new User object and add it to the database with is_approved=False
        new_user = users(
            username=username,
            password=hashed_password,
            full_name=full_name,
            date_of_birth=date_of_birth,
            email=email,
            admin=admin,
            grupo_id=grupo_id,
            registered_on=registered_on,
            access_expiry_date=access_expiry_date
        )
        print("New User:", new_user)
        db.session.add(new_user)
        db.session.commit()

        # Enviar notificação de aprovação pendente apenas se o usuário for um administrador
        send_approval_notification(sender_email, pending_users)
        print("New send_approval_notification:", sender_email)
        print("New pending_users:", pending_users)
            

        return redirect(url_for("index"))
        

    grupos = Grupo.query.all()
    return render_template("register.html", grupos=grupos)



@app.route("/pagamento", methods=["GET", "POST"])
def pagamento():
    if request.method == "POST":
        # Verifica se o pagamento foi recebido com sucesso (por exemplo, por meio de uma integração de pagamento)
        pagamento_recebido = True  # Suponha que o pagamento tenha sido bem-sucedido

        if pagamento_recebido:
            # Atualiza o status do usuário para ativo ou prorroga a data de expiração do acesso
            user = current_user  # Suponha que você tenha acesso ao usuário atual
            user.is_approved = True  # Ou outra lógica para ativar o acesso pago
            db.session.commit()

            flash("Pagamento recebido com sucesso! Seu acesso foi ativado.", "success")
            return redirect(url_for("index"))
        else:
            flash("O pagamento não foi recebido. Por favor, tente novamente.", "error")
            return redirect(url_for("pagamento"))

    return render_template("payment.html")



# Função para enviar um e-mail com instruções de pagamento
def send_payment_email(user):
    msg = Message('Pagamento necessário para continuar acessando', sender='seumkt@gmail.com', recipients=[user.email])
    msg.body = f"""
    Olá {user.full_name},

    Seu período de acesso gratuito ao LigaAdmin está prestes a expirar.
    Para continuar usando a aplicação, é necessário efetuar o pagamento de R$ 30,00.

    Por favor, realize uma transferência PIX para a seguinte chave:

    Chave PIX: (21) 99055-6666
    Nome: THIAGO FIDELES
    Tipo de Chave: Telefone
    Valor: R$ 30,00
    Código da transferência: PAGLIGAADMIN

    Após efetuar o pagamento, por favor, entre em contato conosco para confirmar.

    Atenciosamente,
    Equipe do LigaAdmin
    """
    mail.send(msg)
     



# Rota para servir os arquivos da pasta 'media'
@app.route("/media/<path:filename>")
def media_files(filename):
    return send_from_directory(MEDIA_FOLDER, filename)


# from . import LoginForm
logging.basicConfig(level=logging.DEBUG)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = users.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_approved:
                if user.is_free_access_expired():
                    # Se o acesso gratuito expirou, redirecione o usuário para a página de pagamento
                    return redirect(url_for("pagamento"))
                
                # Login bem-sucedido, redireciona para a página inicial
                login_user(user, remember=True)

                # Defina o grupo_id no objeto current_user
                current_user.grupo_id = user.grupo_id
                
                flash("Login criado!", "sucesso")
                return redirect(url_for("index"))
            else:
                flash("Seu registro está aprovado, mas você ainda não pode acessar a aplicação.", "warning")
        else:
            flash("Nome de usuário ou senha incorretos", "error")

    # Se o formulário não for válido ou se ocorrer um erro, renderize o template login.html
    return render_template("login.html", form=form)



@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()  # Use the logout_user() function to log the user out
    return render_template("logout.html")

#def generate_random_token():
    # Implemente sua lógica para gerar um token aleatório
 #   return 'random_generated_token'

def generate_random_token(token_length=12):
    """Generate a random token."""
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for i in range(token_length))
    return token 


def send_password_reset_email(user_email, token):
    sender_email = "seumkt@gmail.com"
    subject = "Redefinição de Senha"
    reset_url = url_for("reset_password_token", token=token, _external=True)
    body = f"Prezado usuário,\n\nClique no link a seguir para redefinir sua senha:\n\n{reset_url}\n\nCom os melhores cumprimentos,\nO Administrador"

    msg = Message(subject, sender=sender_email, recipients=[user_email])
    msg.body = body

    try:
        print(f"Enviando email para {user_email} com o token {token}")
        mail.send(msg)
        print("Email enviado com sucesso!")
    except Exception as e:
        print("Erro ao enviar email:", e)



@app.route("/edit_password", methods=["GET", "POST"])
@login_required
def edit_password():
    form = PasswordEditForm()

    if form.validate_on_submit():
        user = current_user

        # Verifica se a senha atual corresponde
        if bcrypt.check_password_hash(user.password, form.current_password.data):
            # Gera o novo hash da nova senha
            hashed_new_password = bcrypt.generate_password_hash(
                form.new_password.data
            ).decode("utf-8")
            user.password = hashed_new_password
            db.session.commit()

            flash("Sua senha foi alterada com sucesso.", "success")
            return redirect(url_for("index"))
        else:
            flash("Senha atual incorreta.", "danger")

    return render_template("edit_password.html", form=form)

from datetime import datetime, timezone

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    user = users.query.filter_by(password_reset_token=token).first()
    if user and user.password_reset_expiration > datetime.now(timezone.utc):
        form = PasswordResetForm()

        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
                "utf-8"
            )
            user.password = hashed_password
            user.password_reset_token = None
            user.password_reset_expiration = None
            db.session.commit()

            flash("Sua senha foi redefinida com sucesso.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password_token.html", form=form, token=token)

    flash("O link de redefinição de senha é inválido ou expirou.", "danger")
    return redirect(url_for("login"))

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    form = PasswordResetForm()
    
    if form.validate_on_submit():
        token = generate_random_token()
        print("Generated Token:", token)
        
        user = users.query.filter_by(email=form.email.data).first()
        if user:
            print(f"User Found: {user.username} with email {user.email}")
            user.password_reset_token = token
            user.password_reset_expiration = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()
            print("Token and Expiration Updated")
            
            send_password_reset_email(user.email, token)
            
            flash("Um link de redefinição de senha foi enviado para o seu email.", "info")
            return redirect(url_for("login"))
        else:
            flash("Email não encontrado.", "danger")
            print("User Not Found")

    return render_template("reset_password.html", form=form)


@app.route("/gerencia_usuario", methods=["GET"])
@login_required
def gerencia_usuario():    
    # Recupera os usuários que estão pendentes de aprovação de pagamento
    pending_users = users.query.filter_by().all()
    
    # Calcula quantos dias se passaram desde o registro para cada usuário
    for user in pending_users:
        days_since_registration = (datetime.utcnow() - user.registered_on).days
        user.days_since_registration = days_since_registration
    
    # Renderiza o template com os usuários pendentes de aprovação e informações sobre os dias desde o registro
    return render_template("gerencia_usuario.html", pending_users=pending_users)



@app.route("/pendente_aprovacao", methods=["GET"])
@login_required
def pendente_aprovacao():
    # Verifica se o usuário está autenticado como administrador
    if not current_user.admin:
        return "Apenas administradores podem visualizar usuários pendentes de aprovação.", 403
    
    # Recupera os usuários que estão pendentes de aprovação de pagamento
    pending_users = users.query.filter_by(is_approved=False).all()
    
    # Calcula quantos dias se passaram desde o registro para cada usuário
    for user in pending_users:
        days_since_registration = (datetime.utcnow() - user.registered_on).days
        user.days_since_registration = days_since_registration
    
    # Renderiza o template com os usuários pendentes de aprovação e informações sobre os dias desde o registro
    return render_template("pending_approval.html", pending_users=pending_users)


@app.route("/aprova_usuarios", methods=["POST"])
@login_required
def aprova_usuarios():
    # Verifica se o usuário está autenticado como administrador
    if not current_user.admin:
        return "Apenas administradores podem aprovar usuários.", 403

    # Obtém os IDs dos usuários selecionados para aprovação a partir do formulário
    user_ids = request.form.getlist("user_ids[]")

    # Itera sobre os IDs dos usuários e aprova cada um deles
    for user_id in user_ids:
        user = users.query.get(user_id)
        if user:
            user.is_approved = True
            db.session.commit()

    # Redireciona de volta para a página de usuários pendentes após a aprovação
    return redirect(url_for("pendente_aprovacao"))



# Rota para cadastrar um novo grupo
@app.route("/cadastrar_grupo", methods=["GET", "POST"])
def cadastrar_grupo():
    if request.method == "POST":
        nome_grupo = request.form["nome_grupo"]

        # Verifique se o grupo já existe no banco de dados
        if Grupo.query.filter_by(nome_grupo=nome_grupo).first():
            flash("Este grupo já está cadastrado.", "error")
        else:
            # Crie um novo grupo e adicione ao banco de dados
            novo_grupo = Grupo(nome_grupo=nome_grupo)
            db.session.add(novo_grupo)
            db.session.commit()
            flash("Novo grupo cadastrado com sucesso!", "success")
            return redirect(
                url_for("index")
            )  # Redirecione para a página inicial após o cadastro

    return render_template("cadastrar_grupo.html")


# @app.route('/')
# def inicial():
#   return render_template('inicial.html')


# Rota para registro de jogadores
@app.route("/registro", methods=["GET", "POST"])
@login_required
def registro():
    player = None

    if request.method == "POST":
        name = request.form["name"]
        age = request.form["age"]
        preferencia_pe = request.form.get("preferencia_pe")
        posicao = request.form.get("posicao")
        nota = request.form.get("nota")
        status = request.form.get("status", "yes")
        payment = request.form.get("payment", "no")
        grupo_id = request.form.get(
            "grupo_id"
        )  # Novo campo para armazenar o ID do grupo selecionado

        # Crie um novo jogador com os dados fornecidos pelo formulário
        player = Player(
            name=name, age=age, status=status, payment=payment, grupo_id=grupo_id
        )
        score = Score(
            player=player, preferencia_pe=preferencia_pe, posicao=posicao, nota=nota
        )
        db.session.add(player)
        db.session.add(score)
        db.session.commit()

        return render_template("registro.html", player=player)

    grupos = Grupo.query.all()  # Obtenha todos os grupos do banco de dados
    return render_template("registro.html", player=player, grupos=grupos)


@app.route('/listar_jogadores')
@login_required
def listar_jogadores():
    if current_user.is_authenticated:
        grupo_id_do_usuario = current_user.grupo_id
        jogadores_do_grupo = Player.query.filter_by(grupo_id=grupo_id_do_usuario).all()
        return render_template('jogadores.html', jogadores=jogadores_do_grupo)
    else:
        # Caso o usuário não esteja autenticado, redirecione para a página de login
        return redirect(url_for('login'))


@app.route("/edit_player/<int:player_id>", methods=["GET", "POST"])
@login_required
def edit_player(player_id):
    player = Player.query.get_or_404(player_id)

    # Verifica se o jogador tem uma entrada na tabela Score
    if player.score is None:
        player.score = Score()  # Cria uma nova entrada na tabela Score para o jogador

    if request.method == "POST":
        # Adicione pontos de depuração para verificar os dados recebidos do formulário
        print("Form Data:")
        print(request.form)

        # Atualiza os campos do jogador e da pontuação
        player.name = request.form["name"]
        player.age = request.form["age"]
        player.status = request.form.get("status", "yes")
        player.payment = request.form.get("payment", "no")

        # Adicione mais pontos de depuração para verificar os dados atualizados
        print("Updated Player Data:")
        print("Player Name:", player.name)
        print("Player Age:", player.age)
        print("Player Status:", player.status)
        print("Player Payment:", player.payment)

        # Atualiza os campos da pontuação apenas se o jogador já tiver uma entrada de pontuação
        if player.score:
            player.score.preferencia_pe = request.form.get("preferencia_pe")
            player.score.posicao = request.form.get("posicao")
            player.score.nota = request.form.get("nota")
        else:
            # Se não houver entrada de pontuação, crie uma nova e atualize os campos
            player.score = Score(
                preferencia_pe=request.form.get("preferencia_pe"),
                posicao=request.form.get("posicao"),
                nota=request.form.get("nota"),
            )

        # Adicione mais pontos de depuração para verificar os dados da pontuação atualizados
        if player.score:
            print("Updated Score Data:")
            print("Player Score Preferencia Pe:", player.score.preferencia_pe)
            print("Player Score Posicao:", player.score.posicao)
            print("Player Score Nota:", player.score.nota)
        else:
            print("Player Score: None")

        try:
            db.session.commit()
            print("Dados salvos no banco de dados com sucesso!")
        except Exception as e:
            db.session.rollback()  # Desfaz quaisquer alterações pendentes
            print(f"Erro ao salvar os dados no banco de dados: {str(e)}")
            flash("Erro ao atualizar o jogador. Por favor, tente novamente.", "error")
            return redirect(url_for("listar_jogadores"))

    return render_template("edit_player.html", player=player)


# Rota para deletar um jogador existente
@app.route("/delete_player/<int:player_id>", methods=["POST"])
@login_required
def delete_player(player_id):
    player = Player.query.get_or_404(player_id)
    db.session.delete(player)
    db.session.commit()
    flash("Jogador excluído com sucesso!", "success")
    return redirect(url_for("listar_jogadores"))


@app.route("/calendario", methods=["GET", "POST"])
@login_required
def calendario():

    # Obter todas as datas disponíveis para marcação de partidas
    datas_disponiveis = DiaFut.query.filter_by(dt_encerramento=None).all()

    # Verificar se há datas disponíveis
    #if not datas_disponiveis:
        #flash("Não há partidas disponíveis para marcação no momento.", "info")
        #return redirect(url_for("index"))  # Redirecionar para a página inicial

    return render_template("calendario.html", datas_disponiveis=datas_disponiveis)



# Atualização da rota para adicionar data de partida
@app.route("/adicionar_data_partida", methods=["POST"])
@login_required
def adicionar_data_partida():
    if request.method == "POST":
        nova_data = request.form["nova_data"]
        nova_data = datetime.strptime(nova_data, "%Y-%m-%dT%H:%M")


        local_partida = request.form.get("local_partida")
        if local_partida is None:
            flash('O campo "local_partida" não foi enviado.', "error")

        # Verificar se a data já existe no banco de dados
        if DiaFut.query.filter_by(dt_jogo=nova_data).first():
            flash("A data já está cadastrada.", "error")
        else:
            nova_data_partida = DiaFut(
                dt_jogo=nova_data,
                dt_confirmacao=datetime.now(),
                loca_partida=local_partida,
            )
            db.session.add(nova_data_partida)
            db.session.commit()
            flash("Nova data adicionada com sucesso.", "success")

    return redirect(url_for("calendario"))


# Adição de uma nova rota para associar jogadores às partidas
@app.route("/associar_jogadores_partida", methods=["POST"])
@login_required
def associar_jogadores_partida():
    if request.method == "POST":
        id_partida = request.form["id_partida"]  # ID da partida selecionada

        # Verificar se um ID de partida válido foi fornecido
        if id_partida is None or not id_partida.isdigit():
            flash("ID da partida inválido.", "error")
            return redirect(
                url_for("calendario")
            )  # Redirecionar de volta para a página de calendário

        # Verificar se a partida está ativa
        partida = DiaFut.query.filter_by(id_partida=id_partida, ativo=True).first()
        if not partida:
            flash("Partida não está mais ativa.", "error")
            return redirect(
                url_for("calendario")
            )  # Redirecionar de volta para a página de calendário

        players_selected = request.form.getlist(
            "players_selected"
        )  # Lista de IDs dos jogadores selecionados

        # Verificar se algum jogador foi selecionado
        if players_selected:
            # Iterar sobre os IDs dos jogadores selecionados
            for selected_player_id in players_selected:
                if not PartidaJogador.query.filter_by(
                    player_id=selected_player_id, id_partida=id_partida
                ).first():
                    novo_registro = PartidaJogador(
                        player_id=selected_player_id,
                        id_partida=id_partida,
                        presenca="yes",
                    )
                    db.session.add(novo_registro)
                    db.session.commit()

            flash("Jogadores associados à partida com sucesso.", "success")
        else:
            flash("Nenhum jogador selecionado.", "warning")

    return redirect(url_for("calendario"))


@app.route("/confirmar_presenca", methods=["POST"])
@login_required
def confirmar_presenca():
    if request.method == "POST":
        id_partida = request.form.get("id_partida")  # Obter o ID da partida selecionada
        players_selected = request.form.getlist(
            "players_selected"
        )  # Obter a lista de jogadores selecionados

        # Verificar se um ID de partida válido foi fornecido
        if not id_partida or not id_partida.isdigit():
            flash("ID da partida inválido.", "error")
            return redirect(
                url_for("calendario")
            )  # Redirecionar de volta para a página de calendário

        if id_partida and players_selected:
            # Calcular a data e hora de confirmação da partida
            dt_confirmacao = datetime.now()

            # Calcular a data e hora de encerramento da partida (24 horas após o início)
            dt_encerramento = dt_confirmacao + timedelta(hours=24)

            # Iterar sobre os IDs dos jogadores selecionados
            for player_id in players_selected:
                # Verificar se o jogador já foi confirmado para a partida na data específica
                jogador = PartidaJogador.query.filter_by(
                    player_id=player_id,
                    id_partida=id_partida,
                    dt_confirmacao=dt_confirmacao.date(),
                ).first()
                if jogador:
                    flash("O jogador já foi confirmado para esta partida.", "error")
                    return redirect(
                        url_for("listar_jogadores")
                    )  # Redirecionar de volta para a lista de jogadores

                # Criar um novo registro na tabela PartidaJogador
                novo_registro = PartidaJogador(
                    player_id=player_id,
                    id_partida=id_partida,
                    dt_confirmacao=dt_confirmacao.date(),
                    presenca="yes",
                )
                db.session.add(novo_registro)
                db.session.commit()

            # Atualizar a coluna dt_encerramento na tabela DiaFut com a data e hora de encerramento calculadas
            partida = DiaFut.query.filter_by(id_partida=id_partida).first()
            if partida:
                partida.dt_encerramento = dt_encerramento
                db.session.commit()

            flash("Presença dos jogadores confirmada com sucesso.", "success")
        else:
            # Se o ID da partida ou nenhum jogador foi selecionado, exibir uma mensagem de erro
            flash("Nenhum jogador selecionado ou ID da partida inválido.", "warning")

    return redirect(url_for("listar_jogadores"))


@app.route("/jogadores_confirmados", methods=["GET"])
@login_required
def jogadores_confirmados():
    # Query para obter registros de jogadores confirmados e suas datas de confirmação
    registros_confirmados = (
        db.session.query(Player, PartidaJogador.dt_confirmacao, DiaFut.dt_jogo)
        .join(PartidaJogador, Player.id == PartidaJogador.player_id)
        .join(
            DiaFut,
            PartidaJogador.id_partida
            == DiaFut.id_partida,  # Corrigir o nome do campo de ID
        )
        .filter(PartidaJogador.presenca == "yes")
        .all()
    )
    print(
        "registros_confirmados:", registros_confirmados
    )

    return render_template(
        "jogadores_confirmados.html", registros_confirmados=registros_confirmados
    )


@app.route("/remover_jogador/<int:player_id>", methods=["GET", "POST"])
@login_required
def remover_jogador(player_id):
    # Encontrar o registro do jogador na partida atual pelo ID e atualizar a presença para 'no'
    registro = PartidaJogador.query.filter_by(
        player_id=player_id, presenca="yes"
    ).first()
    if registro:
        registro.presenca = "no"
        db.session.commit()
        flash("Jogador removido da partida com sucesso.", "success")
    else:
        flash("Jogador não encontrado ou não confirmado para a partida.", "error")

    return redirect(url_for("jogadores_confirmados"))


@app.route("/remover_jogador_partida", methods=["POST"])
@login_required
def remover_jogador_partida():
    if request.method == "POST":
        player_id = request.form["player_id"]  # ID do jogador a ser removido da partida

        # Verificar se um ID de jogador válido foi fornecido
        if player_id is None or not player_id.isdigit():
            flash("ID do jogador inválido.", "error")
            return redirect(
                url_for("listar_jogadores")
            )  # Redirecionar de volta para a página de listar jogadores

        # Encontrar o registro do jogador na partida atual pelo ID e atualizar a presença para 'no'
        registro = PartidaJogador.query.filter_by(
            player_id=player_id, presenca="yes"
        ).first()
        if registro:
            registro.presenca = "no"
            db.session.commit()
            flash("Jogador removido da partida com sucesso.", "success")
        else:
            flash("Jogador não encontrado ou não confirmado para a partida.", "error")

    return redirect(url_for("remover_jogador"))


def calculate_ranking():
    # Consulta para obter os dados necessários para o ranking
    ranking_query = (
        db.session.query(
            Player.name,
            func.count(PartidaJogador.id).label("frequency"),
            func.group_concat(PartidaJogador.dt_confirmacao),
            Score.nota,
            Player.age,
            func.sum(Artilheiro.num_gols).label("total_gols"),
        )
        .join(Score)
        .join(PartidaJogador, PartidaJogador.player_id == Player.id)
        .join(DiaFut, DiaFut.id_partida == PartidaJogador.id_partida)
        .join(Artilheiro, Artilheiro.player_id == Player.id)
        .filter(PartidaJogador.presenca == "yes")
        .group_by(Player.name)
        .order_by(Score.nota.desc(), Player.age.asc())
        .all()
    )

    # Formatar os dados do ranking
    ranked_data = []
    for rank, (name, frequency, confirmacao_dates, score, age, total_gols) in enumerate(
        ranking_query
    ):
        # Formatar as datas
        formatted_dates = [
            datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S.%f")
            for date_str in confirmacao_dates.split(",")
        ]
        formatted_dates.sort()
        # Adicionar os dados formatados à lista de dados classificados
        ranked_data.append(
            (
                rank + 1,
                name,
                frequency,
                "\n".join(
                    date.strftime("%d/%m/%Y %H:%M:%S") for date in formatted_dates
                ),
                score,
                age,
                total_gols,
            )
        )

    return ranked_data


@app.route("/ranking")
@login_required
def ranking():
    ranking_data = calculate_ranking()
    print(
        "Ranking Data:", ranking_data
    )  # Adicionando esta linha para verificar os dados do ranking
    players = Player.query.all()
    print(
        "Players:", players
    )  # Adicionando esta linha para verificar os dados dos jogadores
    # Formatando as datas e a idade antes de passá-las para o template
    formatted_ranking_data = list(
        (rank, name, frequency, checkin_dates, score, age, total_gols)
        for rank, name, frequency, checkin_dates, score, age, total_gols in ranking_data
    )
    print(
        "Formatted Ranking Data:", formatted_ranking_data
    )  # Adicionando esta linha para verificar os dados formatados do ranking
    return render_template(
        "ranking.html", ranking=formatted_ranking_data, players=players
    )


def choose_teams(players, total_players, team_size):
    if team_size <= 0:
        raise ValueError("O tamanho do time deve ser maior que zero.")
    
    random.shuffle(players)  # Embaralhar a lista de jogadores

    # Inicializar os times
    num_teams = total_players // team_size
    teams = [[] for _ in range(num_teams)]

    # Separar os goleiros
    goalkeepers = [player for player in players if "Goleiro" in player.name]
    other_players = [player for player in players if "Goleiro" not in player.name]

    # Distribuir os goleiros nos times
    for i, goalkeeper in enumerate(goalkeepers):
        teams[i % num_teams].append(goalkeeper)

    # Distribuir os outros jogadores nos times
    for player in other_players:
        for team in teams:
            if len(team) < team_size:
                team.append(player)
                break

    # Criar uma lista numerada de times
    teams_with_numbers = [(i + 1, team) for i, team in enumerate(teams)]

    return teams_with_numbers


# Rota para selecionar a data do jogo
@app.route("/select_date", methods=["GET", "POST"])
def select_date():
    now = datetime.now()
    datas_disponiveis = DiaFut.query.filter(DiaFut.dt_jogo > now).all()

    if request.method == "POST":
        selected_date = request.form.get("select_date")
        if selected_date:
            return redirect(url_for("teams", selected_date=selected_date))
        else:
            flash("Selecione uma data.", "error")
    
    return render_template("select_date.html", datas_disponiveis=datas_disponiveis)


@app.route("/teams", methods=["GET", "POST"])
@login_required
def teams():
    if request.method == "POST":
        id_partida = request.form.get("id_partida")
        
        if not id_partida or not id_partida.isdigit():
            flash("ID da partida inválido.", "error")
            return redirect(url_for("calendario"))

        partida = DiaFut.query.filter_by(id_partida=id_partida).first()
        if not partida:
            flash("Partida não encontrada.", "error")
            return redirect(url_for("calendario"))

        jogadores_partida = (
            db.session.query(Player)
            .join(PartidaJogador, Player.id == PartidaJogador.player_id)
            .filter(PartidaJogador.id_partida == id_partida)
            .all()
        )

        if not jogadores_partida:
            flash("Nenhum jogador encontrado para esta partida.", "error")
            return redirect(url_for("calendario"))

        total_players = int(request.form.get("total_players", len(jogadores_partida)))
        team_size = int(request.form.get("team_size", total_players // 2))

        if team_size <= 0 or total_players <= 0 or total_players < team_size:
            flash("Número de jogadores ou tamanho dos times inválidos.", "error")
            return redirect(url_for("calendario"))

        teams = choose_teams(jogadores_partida, total_players, team_size)
        return render_template("teams.html", teams=teams, partida=partida)

    # GET request
    selected_date = request.args.get("selected_date")
    if selected_date:
        partidas = DiaFut.query.filter_by(dt_jogo=selected_date).all()
    else:
        partidas = DiaFut.query.all()
        
    return render_template("select_partida.html", partidas=partidas)





@app.route("/add_gols", methods=["GET", "POST"])
@login_required
def add_gols():
    data_partida_str = None  # Definir data_partida_str como None por padrão

    # Recuperar a data da partida do formulário se estiver disponível
    if request.method == "POST":
        data_partida_str = request.form["data_partida"]

        player_id = request.form[
            "player_name"
        ]  # Agora, player_id será o ID do jogador selecionado
        num_gols = request.form["num_gols"]

        # Verificar se o jogador está presente na partida
        player = Player.query.get(player_id)  # Obtém o jogador pelo ID
        if player:
            # Converter a string de data para um objeto datetime
            data_partida = datetime.strptime(data_partida_str, "%Y-%m-%d")

            # Adicionar os gols marcados à tabela de artilheiros
            artilheiro = Artilheiro(
                player=player, num_gols=num_gols, data_partida=data_partida
            )
            db.session.add(artilheiro)
            db.session.commit()
            flash("Gols registrados com sucesso.", "success")
        else:
            flash("Jogador não encontrado.", "error")

    # Recuperar a lista de jogadores
    players = Player.query.all()

    # Recuperar a lista de partidas
    partidas = DiaFut.query.all()

    return render_template("add_gols.html", players=players, partidas=partidas)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
