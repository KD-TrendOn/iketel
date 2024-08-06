from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from uuid import uuid4

db = SQLAlchemy()

def get_uuid():
    return uuid4().hex

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(32), primary_key=True, unique=True, default=get_uuid)
    username = db.Column(db.String(345), unique=True)
    password = db.Column(db.String(100), nullable=False)

class Teacher(User):
    __tablename__ = 'teachers'
    id = db.Column(db.String(32), db.ForeignKey('users.id'), primary_key=True)
    teacher_name = db.Column(db.String(40), unique=True)
    teacher_email = db.Column(db.String(40), unique=True)
    teacher_password = db.Column(db.String(100), nullable=False)

class Story(db.Model):
    __tablename__ = 'stories'
    id = db.Column(db.String(32), primary_key=True)
    story_code = db.Column(db.String(8), unique=True)
    teacher_id = db.Column(db.String(32), db.ForeignKey('teachers.id', ondelete='CASCADE'))
    story_name = db.Column(db.String(30))
    story_desc = db.Column(db.String(500))

class StoryList(db.Model):
    __tablename__ = 'story_list'
    id = db.Column(db.String(32), primary_key=True)
    story_id = db.Column(db.String(32), db.ForeignKey('stories.id', ondelete='CASCADE'))
    story_index = db.Column(db.String(10), nullable=False)
    quest_text = db.Column(db.String(500))

class Character(db.Model):
    __tablename__ = 'characters'
    id = db.Column(db.String(32), primary_key=True)
    story_id = db.Column(db.String(32), db.ForeignKey('stories.id', ondelete='CASCADE'))
    character_desc = db.Column(db.String(500))
    image_path = db.Column(db.String(100))

class Quest(db.Model):
    __tablename__ = 'quests'
    id = db.Column(db.String(32), primary_key=True)
    story_id = db.Column(db.String(32), db.ForeignKey('stories.id', ondelete='CASCADE'))
    quest_name = db.Column(db.String(30), nullable=False)
    quest_theme = db.Column(db.String(30), nullable=False)
    quest_index = db.Column(db.String(10), nullable=False)
    character_id = db.Column(db.String(32), db.ForeignKey('characters.id'))
    quest_text = db.Column(db.String(500))
    character_text = db.Column(db.String(500))

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.String(32), primary_key=True)
    quest_id = db.Column(db.String(32), db.ForeignKey('quests.id', ondelete='CASCADE'))
    content = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.String(200))
    task_index = db.Column(db.String(10), nullable=False)
    task_type = db.Column(db.String(20), nullable=False)

class UsersTask(db.Model):
    __tablename__ = 'users_tasks'
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.String(32), db.ForeignKey('users.id', ondelete='CASCADE'))
    story_id = db.Column(db.String(32), db.ForeignKey('stories.id', ondelete='CASCADE'))
    correct_tasks = db.Column(db.String(10), nullable=False)
    not_correct_tasks = db.Column(db.String(10), nullable=False)