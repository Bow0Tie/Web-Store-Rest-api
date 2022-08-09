from datetime import datetime
from functools import wraps, partial
import traceback
import logging
import asyncio
import sys
import concurrent.futures
from json import dumps, JSONEncoder
from uuid import UUID

from aiohttp import web, ClientSession, BasicAuth

from sqlalchemy.ext.asyncio import create_async_engine

from asyncio_throttle import Throttler
import yaml

from middlewares import auth_middleware, check_role_middleware_factory

routes = web.RouteTableDef()


def exception_handler(method):
    @wraps(method)
    async def wrapper(*args, **kwargs):
        if not (args[0].request.path.startswith('/internal') or args[0].request.path.startswith('/local')):
            return await method(*args, **kwargs)

        try:
            return await method(*args, **kwargs)

        except web.HTTPException:
            raise

        except Exception:
            logging.error(traceback.format_exc())
            raise web.HTTPInternalServerError(text=traceback.format_exc())

    return wrapper


class Core:

    def __init__(self):
        if sys.version_info >= (3, 8) and sys.platform.lower().startswith("win"):
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy())
        self.__logger = self.__init_logger()
        self.__loop = asyncio.get_event_loop()
        self.__executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.__throttler = Throttler(5, 10)
        self.__options = self.__read_config()
        self._db = None
        self.__web = web.Application(middlewares=[auth_middleware, check_role_middleware_factory('ADMIN')])
        self.__loop.create_task(self.__init_db())
        self.__loop.create_task(self.__init_web())

    @staticmethod
    def __init_logger():
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        fmt = '[%(levelname)1.1s %(asctime)s' \
              ' (%(module)s:%(lineno)d)] %(message)s'
        formatter = logging.Formatter(fmt)
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(formatter)
        logger.addHandler(log_handler)
        return logger

    @staticmethod
    def __read_config():
        with open('etc/config.yml', 'r') as config:
            return yaml.load(config, Loader=yaml.Loader)

    async def __init_db(self):
        engine = create_async_engine(self.__options['postgres']['uri'])
        self.__db = engine
        self.logger.info('Database initialised')

    async def __init_web(self):
        app = self.__web
        app.core = self
        app.router.add_routes(routes)
        app.add_routes([web.static('/img', './static', show_index=True, follow_symlinks=True)])
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        options = self.__options['server']
        site = web.TCPSite(runner, options['host'], options['port'])
        await site.start()
        self.logger.info('Web server initialised')

    @property
    def loop(self):
        return self.__loop

    @property
    def logger(self):
        return self.__logger

    @property
    def executor(self):
        return self.__executor

    @property
    def throttler(self):
        return self.__throttler

    @property
    def db(self):
        return self.__db

    @property
    def web(self):
        return self.__web

    @property
    def options(self):
        return self.__options


class ServiceView(web.View):

    def __init__(self, *args, **kwargs):
        logging.info(f'R {args[0].method} {args[0].path_qs}')
        super().__init__(*args, **kwargs)
        self.__core = instance

    @property
    def loop(self):
        return self.__core.loop

    @property
    def logger(self):
        return self.__core.logger

    @property
    def web(self):
        return self.__core.web

    @property
    def db(self):
        return self.__core.db

    @property
    def executor(self):
        return self.__core.executor

    @property
    def throttler(self):
        return self.__core.throttler

    @property
    def options(self):
        return self.__core.options

    @staticmethod
    async def http_request(method, url, params=None, auth=None, json=None, headers=None):
        logging.info(f'S {method} {url}')
        auth_data = BasicAuth(
            login=auth['login'], password=auth['password']) if auth else None

        async with ClientSession(raise_for_status=True, auth=auth_data,
                                 json_serialize=partial(dumps, cls=ServiceResponseEncoder)) as session:
            if method == 'GET':
                session_method = session.get
            elif method == 'POST':
                session_method = session.post
            elif method == 'PUT':
                session_method = session.put

            async with session_method(url, params=params, json=json, headers=headers) as resp:
                if 'text' in resp.content_type:
                    return await resp.text()
                elif 'json' in resp.content_type:
                    return await resp.json()
                else:
                    logging.error('Unknown content_type')
                    return resp

    @staticmethod
    def json_response(data, status=200):
        return web.json_response(data=data, status=status, dumps=partial(dumps, cls=ServiceResponseEncoder))


class ServiceResponseEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, UUID):
            return str(obj)
        elif isinstance(obj, datetime):
            return str(obj)
        return JSONEncoder.default(self, obj)


instance = Core()
