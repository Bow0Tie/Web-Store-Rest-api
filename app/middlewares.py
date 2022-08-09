from aiohttp import web
import jwt
import re

import sqlalchemy.exc



@web.middleware
async def auth_middleware(request, handler):
    """
    Middleware check Authorization and add user data to request.
    Use Bearer token Header.
    """
    if request.method == 'OPTIONS':
        response = await handler(request)
        return response

    if not (request.path == '/user/auth'):
        response = await handler(request)
        return response

    try:
        options = request.app.core.options
        token = request.headers["Authorization"].split(' ')[1]

        decoded_token = jwt.decode(
            token,
            options['authorization']['secret_key'],
            algorithms=["HS256"]
        )

        request["user"] = decoded_token
        response = await handler(request)
        return response
    except KeyError:
        raise web.HTTPBadRequest(
                text='You have not specified name value')
    except Exception:
        raise web.HTTPUnauthorized


def check_role_middleware_factory(role):
    """
    Middleware check permission for adding and deleting Categories, Brands and Devices.
    :param role: The role that is allowed to add or delete.
    """

    @web.middleware
    async def check_role_middleware(request, handler):
        if not (
                request.method == 'POST' or
                request.method == 'DELETE'
        ):
            response = await handler(request)
            return response

        if not (
                request.path == '/category' or
                request.path == '/brand' or
                request.path == '/device' or
                re.findall('/device/.', request.path)
        ):
            response = await handler(request)
            return response

        try:
            options = handler(request).options
            try:
                token = request.headers["Authorization"].split(' ')[1]
            except KeyError:
                raise web.HTTPUnauthorized

            decoded_token = jwt.decode(
                token,
                options['authorization']['secret_key'],
                algorithms=["HS256"]
            )

            if not (decoded_token["role"] == role):
                raise web.HTTPForbidden

            request["user"] = decoded_token
            response = await handler(request)
            return response
        except web.HTTPForbidden:
            raise
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified required body values') from e
        except sqlalchemy.exc.IntegrityError:
            raise web.HTTPBadRequest(
                text='Value already exist')
        except jwt.exceptions.DecodeError:
            raise web.HTTPUnauthorized
    return check_role_middleware
