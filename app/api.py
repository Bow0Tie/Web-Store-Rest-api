from aiohttp import web
from core import routes, ServiceView

import sqlalchemy as sa

import os
import hashlib
import jwt

import db

# select query for build Device info object
gdi = (
    sa.select([
        db.DeviceInfo.device_id,
        sa.func.array_agg(sa.func.json_build_object(
            'id', db.DeviceInfo.id,
            'title', db.DeviceInfo.title,
            'description', db.DeviceInfo.description,
            'created', db.DeviceInfo.created,
            'device_id', db.DeviceInfo.device_id
        ))
        .label("device_info")
    ])
    .group_by(db.DeviceInfo.device_id)
    .alias("gdi")
)


def generate_jwt(user_id, email, role, salt):
    """
    Generate JSON web token by User parameters
    """
    return jwt.encode(
        {"id": user_id, "email": email, "role": role},
        salt,
        algorithm="HS256"
    )


@routes.view('/user/registration')
class UserReg(ServiceView):
    async def post(self):
        """
        Receive Email and Password and possible Role.
        Hash Password and add User into DB. Generate Json web token.
        :return: Generated Json web token.
        """
        try:
            body = await self.request.json()
            email, password = list(body.values())[:2]
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified email or password') from e

        try:
            role = body["role"]
        except KeyError:
            role = None

        select = sa.select(db.User).where(db.User.email == email)
        async with self.db.connect() as conn:
            result = await conn.execute(select)
            row = result.fetchone()

        if row:
            raise web.HTTPBadRequest(
                text='This e-mail already exist')

        hash_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self.options['authorization']['salt'].encode('utf-8'),
            100000
        )

        insert = (
            sa.insert(db.User)
            .returning(db.User.id, db.User.role)
            .values(
                email=email,
                password=str(hash_password)
            )
        )

        if role:
            insert = insert.values(role=role)

        async with self.db.begin() as conn:
            inserted_user = await conn.execute(insert)

            user_dict = dict(inserted_user.fetchone())

            await conn.execute(
                sa.insert(db.Basket)
                .values(user_id=int(user_dict["id"]))
            )

        token = generate_jwt(
            int(user_dict["id"]),
            email,
            user_dict["role"],
            self.options['authorization']['secret_key']
        )
        return self.json_response({"token": token})


@routes.view('/user/login')
class UserLogin(ServiceView):
    async def post(self):
        """
        Receive Email and Password. Checks correctness of password.
        Generate Json web token.
        :return: Generated Json web token.
        """
        try:
            body = await self.request.json()
            email, password = body.values()
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified email or password') from e

        select = sa.select(db.User).where(db.User.email == email)
        async with self.db.connect() as conn:
            result = await conn.execute(select)
            row = result.fetchone()

        if not row:
            raise web.HTTPBadRequest(
                text='User not found')
        user = dict(row)

        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self.options['authorization']['salt'].encode('utf-8'),
            100000
        )

        if not (str(new_key) == user["password"]):
            raise web.HTTPBadRequest(
                text='Password is incorrect')

        token = generate_jwt(
            user["id"],
            user["email"],
            user["role"],
            self.options['authorization']['secret_key']
        )
        return self.json_response({"token": token})


@routes.view('/user/auth')
class UserReg(ServiceView):
    async def get(self):
        """
        Generate Json web token. Using auth_middleware for check authorization.
        :return: Generated Json web token.
        """
        token = generate_jwt(
            self.request["user"]["id"],
            self.request["user"]["email"],
            self.request["user"]["role"],
            self.options['authorization']['secret_key']
        )
        return self.json_response(self.request["user"] | {"token": token})


@routes.view('/category')
class Category(ServiceView):
    async def get(self):
        """
        Select all Categorise from DB.
        """
        select = sa.select(db.Category).order_by(db.Category.id)
        async with self.db.connect() as conn:
            result = await conn.execute(select)
            rows = result.fetchall()
        return self.json_response([dict(row) for row in rows])

    async def post(self):
        """
        Add Category by Name. Use check_role_middleware.
        """
        try:
            body = await self.request.json()
            name = body["name"]
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified name value') from e

        async with self.db.begin() as conn:
            await conn.execute(
                sa.insert(db.Category)
                .values(name=name)
            )
        return web.Response(text=str(name))

    async def delete(self):
        """
        Delete category by Name. Use check_role_middleware.
        """
        try:
            body = await self.request.json()
            name = body["name"]
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified name value') from e

        delete = (
            sa.delete(db.Category).
            where(db.Category.name == name)
        )
        async with self.db.begin() as conn:
            await conn.execute(delete)
        return web.HTTPOk()


@routes.view('/brand')
class Brand(ServiceView):
    async def get(self):
        """
        Select all Brands from DB.
        """
        select = sa.select(db.Brand).order_by(db.Brand.id)
        async with self.db.connect() as conn:
            result = await conn.execute(select)
            rows = result.fetchall()
        return self.json_response([dict(row) for row in rows])

    async def post(self):
        """
        Add Brand by Name. Use check_role_middleware.
        """
        try:
            body = await self.request.json()
            name = body["name"]
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified name value') from e

        async with self.db.begin() as conn:
            await conn.execute(
                sa.insert(db.Brand)
                .values(name=name)
            )
        return web.Response(text=str(name))

    async def delete(self):
        """
        Delete Brand by Name. Use check_role_middleware.
        """
        try:
            body = await self.request.json()
            name = body["name"]
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified name value') from e

        delete = (
            sa.delete(db.Brand).
            where(db.Brand.name == name)
        )
        async with self.db.begin() as conn:
            await conn.execute(delete)
        return web.HTTPOk()


@routes.view('/device')
class Device(ServiceView):
    async def get(self):
        """
        Return Devices from DB by Bran and Category ID
        """
        brand_id, category_id = None, None
        select = None
        page = 1
        limit = 9

        try:
            page = int(self.request.query["page"])
        except KeyError:
            pass
        try:
            limit = int(self.request.query["limit"])
        except KeyError:
            pass
        try:
            brand_id = self.request.query["brand_id"]
        except KeyError:
            pass
        try:
            category_id = self.request.query["category_id"]
        except KeyError:
            pass

        offset = page * limit - limit

        if not brand_id and not category_id:
            select = (
                sa.select([db.Device, gdi.c.device_info])
                .select_from(sa.outerjoin(db.Device, gdi, db.Device.id == gdi.c.device_id))
            )

        if brand_id and not category_id:
            select = (
                sa.select([db.Device, gdi.c.device_info])
                .where(db.Device.brand_id == int(brand_id))
                .select_from(sa.outerjoin(db.Device, gdi, db.Device.id == gdi.c.device_id))
            )

        if not brand_id and category_id:
            select = (
                sa.select([db.Device, gdi.c.device_info])
                .where(db.Device.category_id == int(category_id))
                .select_from(sa.outerjoin(db.Device, gdi, db.Device.id == gdi.c.device_id))
            )

        if brand_id and category_id:
            select = (
                sa.select([db.Device, gdi.c.device_info])
                .where(
                    db.Device.brand_id == int(brand_id),
                    db.Device.category_id == int(category_id)
                )
                .select_from(sa.outerjoin(db.Device, gdi, db.Device.id == gdi.c.device_id))
            )

        select_count = sa.select([sa.func.count()]).select_from(db.Device)

        async with self.db.connect() as conn:
            result = await conn.execute(select
                                        .limit(limit)
                                        .offset(offset)
                                        )
            count = await conn.execute(select_count)

            rows = result.fetchall()
            rows_count = count.fetchone()
        return self.json_response(dict(rows_count) | {"rows": [dict(row) for row in rows]})

    async def post(self):
        """
        Add Device into DB. Use check_role_middleware.
        """
        image = None

        try:
            body = await self.request.json()
            name, price, brand_id, category_id, img, info = body.values()
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified columns value') from e

        for (dir_path, _, filenames) in os.walk("./static"):
            for filename in filenames:
                if img in filename:
                    image = os.path.join(dir_path, filename)

        try:
            insert = sa.insert(db.Device) \
                .returning(db.Device.id) \
                .values(
                name=name,
                price=int(price),
                brand_id=int(brand_id),
                category_id=int(category_id)
            )
            if image:
                insert = insert.values(img=image)

            async with self.db.begin() as conn:
                inserted_device_id = await conn.execute(insert)
                int_device_id = int(dict(inserted_device_id.fetchone())["id"])
                for i in info:
                    await conn.execute(
                        sa.insert(db.DeviceInfo)
                        .values(
                            title=i["title"],
                            description=i["description"],
                            device_id=int_device_id
                        )
                    )
        except(KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text=str(e)) from e
        return web.HTTPOk()


@routes.view('/device/{device_id}')
class DeviceOne(ServiceView):
    async def get(self):
        """
        Select Device from DB by ID.
        """
        device_id = self.request.match_info['device_id']

        select = (
            sa.select([db.Device, gdi.c.device_info])
            .where(db.Device.id == int(device_id))
            .select_from(sa.outerjoin(db.Device, gdi, db.Device.id == gdi.c.device_id))
        )

        async with self.db.connect() as conn:
            result = await conn.execute(select)
            rows = result.fetchall()
        return self.json_response([dict(row) for row in rows])

    async def delete(self):
        """
        Delete Device from DB by ID. Use check_role_middleware.
        """
        device_id = self.request.match_info['device_id']

        delete = (
            sa.delete(db.Device).
            where(db.Device.id == int(device_id))
        )
        async with self.db.begin() as conn:
            await conn.execute(delete)
        return web.HTTPOk()
