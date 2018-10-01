import datetime

from flask_bcrypt import generate_password_hash
from flask_login import UserMixin
from peewee import *

DATABASE = SqliteDatabase('journals.db')


class BaseModel(Model):
    class Meta:
        database = DATABASE

class User(UserMixin, BaseModel):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    @classmethod
    def create_user(cls, username, email, password, admin=False):
        try:
            with DATABASE.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_admin=admin)
        except IntegrityError:
            raise ValueError("User already exists")


class Caller(BaseModel):
    name = CharField()


class Tag(BaseModel):
    name = CharField(unique=True)

    @classmethod
    def create_tag(cls, name):
        try:
            with DATABASE.transaction():
                cls.create(name=name)
        except IntegrityError:
            raise ValueError("Tag already exists")

class SupportEntry(BaseModel):
    is_agent_support = BooleanField(default=True)
    problem = TextField()
    solution = TextField()

    @classmethod
    def create_support_entry(cls, title, is_agent_support, problem, solution, tags):
        try:
            with DATABASE.transaction():
                cls.create(
                    title=title,
                    is_agent_support=is_agent_support,
                    problem=problem,
                    solution=solution,
                    tags=tags
                )
        except IntegrityError:
            raise ValueError("Entry already exists")


class SupportEntryTags(BaseModel):
    support_entry = ForeignKeyField(SupportEntry)
    tag = ForeignKeyField(Tag)


class Issue(BaseModel):
    caller = ForeignKeyField(
        rel_model=Caller,
        related_name='issues'
    )
    csr = ForeignKeyField(
        rel_model=User,
        related_name='problem_reports'
    )
    created_at = DateTimeField(default=datetime.datetime.now)
    closed_at = DateTimeField()
    problem = TextField()
    solution = ForeignKeyField(rel_model=SupportEntry)
    tags = ForeignKeyField(rel_model=Tag)
    notes = TextField()


class Agency(BaseModel):
    code = CharField(unique=True)
    name = CharField()
    location = TextField()
    phone_number = CharField()

    @classmethod
    def create_agency(cls,code,name,location,phone_number):
        try:
            with DATABASE.transaction():
                cls.create(
                    code=code,
                    name=name,
                    location=location,
                    phone_number=phone_number
                )
        except IntegrityError:
            raise ValueError('Agency already exitst')


class Agent(Caller):
    agency = ForeignKeyField(Agency)


class Insured(Caller):
    phone_number = CharField()
    policy_number = CharField()


def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User, SupportEntry, Caller, Agent, Insured, Agency, Tag], safe=True)
    try:
        User.create_user(
            username='Gman',
            email='gman@gmail.com',
            password='password'
        )
        Agency.create_agency(
            code='5121',
            name='Joe Bobs Insurance',
            location='212 Agency St. Tulsa Ok, 74105',
            phone_number='555-555-5555'
        )

        Tag.create_tag(name="NewBusiness")
        Tag.create_tag(name="SystemError")
        SupportEntry.create_support_entry(
            title='Something Broke',
            is_agent_support=True,
            problem='The thingy is connecting to the other thing.',
            solution='I will need to do some more research.  What is a good call back number?',
            tags=Tag.select()
        )
    except ValueError:
        pass

    user = User.select().get()

    DATABASE.close()
