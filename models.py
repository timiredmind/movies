from sqlalchemy import (create_engine, Column, Integer, String, PickleType, Float)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.mutable import MutableList
import bcrypt, random, string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

engine = create_engine("sqlite:///user.db", connect_args={"check_same_thread":False})
Base = declarative_base()
Base.metadata.bind = engine
# Session = sessionmaker(bind=engine)
# session = Session()
secret_key = "".join(random.choice(string.ascii_uppercase+string.digits) for x in range(32))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    hashed_password = Column(String(64))

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        passwd = bytes(password, "utf-8")
        self.hashed_password = bcrypt.hashpw(passwd, salt)

    def verify_password(self, password):
        password = bytes(password, "utf-8")
        return bcrypt.checkpw(password, self.hashed_password)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except BadSignature:
            return None
        except SignatureExpired:
            return None
        user_id = data["id"]
        return user_id


class Movie(Base):
    __tablename__ = "top_movies"
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    year_of_release = Column(Integer)
    rating = Column(Float)
    director = Column(String)
    cast = Column(MutableList.as_mutable(PickleType))

    @property
    def serialize(self):
        return {"id": self.id,
                "title": self.title,
                "year_of_release": self.year_of_release,
                "rating": self.rating,
                "director": self.director,
                "cast": self.cast
                }


Base.metadata.create_all(engine)


# from csv import reader
# with open("imdb_top_250_movies.csv", mode="r") as f:
#     csv_reader = reader(f)
#     next(csv_reader)
#     for row in csv_reader:
#         title = row[1].strip()
#         year_of_release = row[2].strip()
#         rating = float(row[3].strip())
#         director = row[4].strip()
#         cast = row[5].strip()[1:-1].replace("'", "").split(", ")
#         movie = Movie(title=title, year_of_release=year_of_release, rating=rating, director=director, cast=cast)
#         session.add(movie)
#         session.commit()
#
#     f.close()
