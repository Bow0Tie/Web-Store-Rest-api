from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
from sqlalchemy import (
    Column, ForeignKey, Integer,
    String, DateTime
)

Base = declarative_base()


class User(Base):
    """
    Table contains store Users.
    """
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="USER")
    created = Column(DateTime, server_default=func.now())


class Basket(Base):
    """
    Table contains Users Baskets.
    """
    __tablename__ = "basket"
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, server_default=func.now())

    user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete='CASCADE')
    )


class Device(Base):
    """
    Table contains products.
    """
    __tablename__ = "device"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    price = Column(Integer, nullable=False)
    rating = Column(Integer, default=0)
    img = Column(String, nullable=False)
    created = Column(DateTime, server_default=func.now())

    category_id = Column(
        Integer,
        ForeignKey("category.id", ondelete='CASCADE')
    )
    brand_id = Column(
        Integer,
        ForeignKey("brand.id", ondelete='CASCADE')
    )


class BasketDevice(Base):
    """
    Table connect Baskets and Devices.
    """
    __tablename__ = "basket_device"
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, server_default=func.now())

    basket_id = Column(
        Integer,
        ForeignKey('basket.id', ondelete='CASCADE')
    )

    device_id = Column(
        Integer,
        ForeignKey('device.id', ondelete='CASCADE')
    )


class CategoryBrand(Base):
    """
    Table connect Brands and Categories.
    """
    __tablename__ = "category_brand"

    category_id = Column(
        ForeignKey('category.id', ondelete='CASCADE'),
        primary_key=True)
    brand_id = Column(
        ForeignKey('brand.id', ondelete='CASCADE'),
        primary_key=True)
    created = Column(DateTime, server_default=func.now())


class Category(Base):
    """
    Table contains Categories of products.
    """
    __tablename__ = "category"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    created = Column(DateTime, server_default=func.now())


class Brand(Base):
    """
    Tabel contains products Brands.
    """
    __tablename__ = "brand"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    created = Column(DateTime, server_default=func.now())


class Rating(Base):
    """
    Tabel contains Device Ratings.
    """
    __tablename__ = "rating"
    id = Column('id', Integer, primary_key=True)
    rate = Column('rate', Integer, nullable=False)
    created = Column(DateTime, server_default=func.now())

    user_id = Column(
        Integer,
        ForeignKey('user.id', ondelete='CASCADE')
    )
    device_id = Column(
        Integer,
        ForeignKey('device.id', ondelete='CASCADE')
    )


class DeviceInfo(Base):
    """
    Table contains information about Devices.
    """
    __tablename__ = "device_info"
    id = Column('id', Integer, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    created = Column(DateTime, server_default=func.now())

    device_id = Column(
        Integer,
        ForeignKey('device.id', ondelete='CASCADE')
    )
