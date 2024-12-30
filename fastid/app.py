from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates 
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.requests import Request
from pydantic_settings import BaseSettings, SettingsConfigDict
from authlib.integrations.starlette_client import OAuth
from urllib.parse import urlencode, quote_plus
from starlette.middleware.sessions import SessionMiddleware
from json import dumps

"Api protegida pela oath0"
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env')  
    DOMAIN: str
    CLIENT_ID: str
    CLIENT_SECRET: str
    SECRET_KEY: str  # Será carregado do arquivo .env
    AUDIENCE: str = ''  # Para quem é a API

# Instância que carregará as configurações do .env
settings = Settings()

# Configuração do OAuth- registrar o cliente
# cuidar dos cookies, redirecionamento, etc
# login logout
OAuth = OAuth()
OAuth.register(
    'auth0',
    client_id=settings.CLIENT_ID,
    client_secret=settings.CLIENT_SECRET,
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url=f'https://{settings.DOMAIN}/.well-known/openid-configuration',
)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
app.mount(
    '/static',
    StaticFiles(directory='static'),name='static')

def to_pretty_json(obj: dict) -> str:
    return dumps(obj, default=lambda x: dict(x), indent=4)


templates = Jinja2Templates(directory='templates')
templates.env.filters['to_pretty_json'] = to_pretty_json


# Deve informar o tipo de resposta que será retornada
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request, name='home.html'
    ) 

@app.get('/login')
async def login(request: Request):
    # session vai existir durante o request
    if not 'id_token' in request.session:
        return await OAuth.auth0.authorize_redirect(
            request,
            redirect_uri=request.url_for('callback'),
            audience=settings.AUDIENCE
        )
    
    return RedirectResponse(url=request.url_for('home'))

@app.get('/logout')
async def logout(request: Request):
    response = RedirectResponse(
        url='https://'
        + settings.DOMAIN
        + '/v2/logout?'
        + urlencode(
            {
                'returnTo': request.url_for('home'),
                'client_id': settings.CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )
    request.session.clear()
    return response

# Criar a session e colocar o id_token
@app.get('/callback')
async def callback(request: Request):
    token = await OAuth.auth0.authorize_access_token(request)
    request.session['access_token'] = token['access_token']
    request.session['id_token'] = token['id_token']
    request.session['userinfo'] = token['userinfo']
    return RedirectResponse(url=request.url_for('home'))

@app.get('/profile')
async def profile(request: Request):
    return templates.TemplateResponse(
        request=request, name='profile.html',
        context={'request': request,
                 'userinfo': request.session['userinfo']}
    )