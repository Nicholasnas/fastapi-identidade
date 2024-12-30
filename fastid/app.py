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
    AUDIENCE: str = ''  # Publico alvo da api - opcional

# Instância que carregará as configurações do .env
settings = Settings()

# configuração do OAuth com o Auth0
# Configuração do OAuth- registrar o cliente
# cuidar dos cookies, redirecionamento, etc
# login logout
OAuth = OAuth()
OAuth.register(
    'auth0', # provedor
    client_id=settings.CLIENT_ID, 
    client_secret=settings.CLIENT_SECRET,
    client_kwargs={'scope': 'openid profile email'}, # escopos solicitados
    server_metadata_url=f'https://{settings.DOMAIN}/.well-known/openid-configuration', # url de configuração do openid
)

app = FastAPI()

# middleware para gerenciar a sessoes e cookies do usuario
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Configuração de arquivos estáticos como css, js e imagens
app.mount(
    '/static',
    StaticFiles(directory='static'),name='static')

# Função auxiliar para converter objetos em JSON formatado
def to_pretty_json(obj: dict) -> str:
    return dumps(obj, default=lambda x: dict(x), indent=4)

# Configura os templates e adiciona um filtro personalizado
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
    """Verifica se o token de ID está presente na sessão"""
    if not 'id_token' in request.session:
        # Se não estiver presente, redireciona para a página de login
        return await OAuth.auth0.authorize_redirect(
            request,
            redirect_uri=request.url_for('callback'), # url de callback apos login
            audience=settings.AUDIENCE
        )
    # Usuário autenticado
    return RedirectResponse(url=request.url_for('home'))

@app.get('/logout')
async def logout(request: Request):
    """Redireciona para o endpoint de logout do Auth0"""
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
    # limpara a sessao do usuario
    request.session.clear()
    return response

# Rota de callback: gerencia a resposta do Auth0 após login
@app.get('/callback')
async def callback(request: Request):
    """Obtem os tokens do Auth0"""
    token = await OAuth.auth0.authorize_access_token(request)
    # Salvar os tokens e informaçoes do user na session
    request.session['access_token'] = token['access_token']
    request.session['id_token'] = token['id_token']
    request.session['userinfo'] = token['userinfo']
    # retornar para a pagina principal - home
    return RedirectResponse(url=request.url_for('home'))

@app.get('/profile')
async def profile(request: Request):
    """Exibir as informações do usuário autenticado"""
    return templates.TemplateResponse(
        request=request, 
        name='profile.html', # Rederizar o template profile
        context={'request': request,
                 'userinfo': request.session['userinfo'] # passar informações do usuario para o template
                 }
                 
    )