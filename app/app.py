import json
from typing import Union, Callable, Awaitable

from aiohttp import web, BasicAuth
from sqlalchemy import Column, Integer, String, DateTime, func, ForeignKey
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
import pydantic
import bcrypt

PG_DSN = 'postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/netology_ads'

engine = create_async_engine(PG_DSN)
Base = declarative_base()
Session = sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)

app = web.Application()


async def orm_context(app: web.Application):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app.cleanup_ctx.append(orm_context)


@web.middleware
async def auth_middleware(
        request: web.Request, handler: Callable[[web.Request], Awaitable[web.Response]]
) -> web.Response:
    auth_header = request.headers.get('Authorization')
    try:
        auth = BasicAuth.decode(auth_header=auth_header)
    except:
        auth = None
        raise web.HTTPForbidden(text=json.dumps({'status': 'error', 'description': 'authentication required'}),
                                content_type='application/json')

    if auth is not None:
        email = auth.login
        password = auth.password
        request['authorization'] = {'username': email, 'password': password}

        if not await verify_password(email, password):
            raise web.HTTPUnauthorized(
                text=json.dumps({'status': 'error', 'description': 'incorrect login or password'}),
                content_type='application/json')

    return await handler(request)


def hash_password(password: str):
    password = password.encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed.decode()


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
    ads = relationship('AdModel', backref='user')

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password.encode())


class AdModel(Base):
    __tablename__ = "ads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(String)
    created_on = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))


class CreateUserSchema(pydantic.BaseModel):
    email: str
    password: str


class CreateAdSchema(pydantic.BaseModel):
    title: str
    description: str
    user_id: int


def validate(data: dict, schema_class):
    try:
        return schema_class(**data).dict()
    except pydantic.ValidationError as er:
        raise web.HTTPBadRequest(text=json.dumps(er.errors()[0]),
                                 content_type='application/json')


class APIException(Exception):
    def __init__(self, status_code: int, message: Union[str, list, dict]):
        self.status_code = status_code
        self.message = message


async def verify_password(email, password):
    async with Session() as session:
        query = select(UserModel).where(UserModel.email == email)
        result = await session.execute(query)
        user = result.scalar()
        if not user or not user.verify_password(password):
            return False
        return True


async def owner_user(email, ad_user_id):
    async with Session() as session:
        query = select(UserModel).where(UserModel.email == email)
        result = await session.execute(query)
        user = result.scalar()
        if not user or not user.id == ad_user_id:
            return False
        return True


class UserView(web.View):

    async def get(self):
        user_id = int(self.request.match_info["user_id"])
        async with Session() as session:
            user = await session.get(UserModel, user_id)
            if user is None:
                raise web.HTTPNotFound(text=json.dumps({'status': 'error', 'description': 'user not found'}),
                                       content_type='application/json')

            return web.json_response({
                'id': user.id,
                'email': user.email
            })

    async def post(self):
        raw_user_data = await self.request.json()
        user_data = validate(raw_user_data, CreateUserSchema)
        user_data['password'] = hash_password(user_data['password'])
        async with Session() as session:
            new_user = UserModel(**user_data)
            session.add(new_user)
            try:
                await session.commit()
            except IntegrityError:
                raise web.HTTPBadRequest(text=json.dumps({'status': 'error', 'description': 'email is busy'}),
                                         content_type='application/json')

            return web.json_response({
                'id': new_user.id,
                'email': new_user.email
            })

    async def patch(self):
        user_id = int(self.request.match_info["user_id"])
        user_data = await self.request.json()
        if 'password' in user_data:
            user_data['password'] = hash_password(user_data['password'])
        async with Session() as session:
            user = await session.get(UserModel, user_id)
            for field, value in user_data.items():
                setattr(user, field, value)
            session.add(user)
            try:
                await session.commit()
            except IntegrityError:
                raise web.HTTPBadRequest(text=json.dumps({'status': 'error', 'description': 'email is busy'}),
                                         content_type='application/json')

            return web.json_response({
                'id': user.id,
                'email': user.email
            })

    async def delete(self):
        user_id = int(self.request.match_info["user_id"])
        async with Session() as session:
            user = await session.get(UserModel, user_id)
            await session.delete(user)
            await session.commit()
            return web.json_response({'status': 'deleted'})


class AdView(web.View):

    async def get(self):
        ad_id = int(self.request.match_info["ad_id"])
        async with Session() as session:
            ad = await session.get(AdModel, ad_id)
            if ad is None:
                raise web.HTTPNotFound(text=json.dumps({'status': 'error', 'description': 'ad not found'}),
                                       content_type='application/json')
            return web.json_response({
                'id': ad.id,
                'title': ad.title,
                'description': ad.description,
                'user_id': ad.user_id
            })

    async def post(self):
        raw_ad_data = await self.request.json()
        ad_data = validate(raw_ad_data, CreateAdSchema)
        async with Session() as session:
            new_ad = AdModel(**ad_data)
            session.add(new_ad)
            await session.commit()

            return web.json_response({
                'id': new_ad.id,
                'title': new_ad.title,
                'description': new_ad.description,
                'user_id': new_ad.user_id
            })

    async def patch(self):
        ad_id = int(self.request.match_info["ad_id"])
        ad_data = await self.request.json()
        async with Session() as session:
            ad = await session.get(AdModel, ad_id)
            if not await owner_user(self.request['authorization'].get('username'), ad.user_id):
                raise web.HTTPForbidden(text=json.dumps({'status': 'error', 'description': 'auth error'}),
                                        content_type='application/json')
            for field, value in ad_data.items():
                setattr(ad, field, value)
            session.add(ad)
            await session.commit()

            return web.json_response({
                'id': ad.id,
                'title': ad.title,
                'description': ad.description,
                'user_id': ad.user_id
            })

    async def delete(self):
        ad_id = int(self.request.match_info["ad_id"])
        async with Session() as session:
            ad = await session.get(AdModel, ad_id)
            if not await owner_user(self.request['authorization'].get('username'), ad.user_id):
                raise web.HTTPForbidden(text=json.dumps({'status': 'error', 'description': 'auth error'}),
                                        content_type='application/json')
            await session.delete(ad)
            await session.commit()
            return web.json_response({'status': 'deleted'})


app.add_routes([
    web.get('/users/{user_id:\d+}', UserView),
    web.patch('/users/{user_id:\d+}', UserView),
    web.delete('/users/{user_id:\d+}', UserView),
    web.post('/users/', UserView),

    web.get('/ads/{ad_id:\d+}', AdView),

])

app_auth_required = web.Application(middlewares=[auth_middleware])
app_auth_required.add_routes(
    [
        web.post("/", AdView),
        web.patch("/{ad_id:\d+}", AdView),
        web.delete("/{ad_id:\d+}", AdView),
    ]
)
app.add_subapp(prefix="/ads", subapp=app_auth_required)

if __name__ == '__main__':
    web.run_app(app)
