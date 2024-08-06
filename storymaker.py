import os
from dotenv import load_dotenv
load_dotenv()

os.environ['LANGCHAIN_TRACING_V2'] = os.getenv("LANGCHAIN_TRACING_V2")
os.environ['LANGCHAIN_API_KEY'] = os.getenv("LANGCHAIN_API_KEY")
os.environ['LANGCHAIN_PROJECT'] = os.getenv("LANGCHAIN_PROJECT")
os.environ['LANGCHAIN_ENDPOINT'] = os.getenv("LANGCHAIN_ENDPOINT")


from langchain.output_parsers import PydanticOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field, validator, ValidationError
from typing import Optional, Literal
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain.output_parsers import PydanticOutputParser
from langchain_core.output_parsers.string import StrOutputParser
from openai import OpenAI
from langsmith import wrappers
from image_generation import image_generate

llm = ChatOpenAI(
        temperature=0.3,
        model="openai/gpt-4o",#openai/gpt-4o
        openai_api_key=os.getenv("OPENROUTER_API_KEY"),
        openai_api_base="https://openrouter.ai/api/v1",
    )

#classes:

class ConceptNPC(BaseModel):
    name: str
    look_description: str
    character_description: str
    image_url: Optional[str]=''

class ConceptFields(BaseModel):
    description: str
    additional_requirements: Optional[str]
    themes: list[str] = []
    npcs_list: list[ConceptNPC] = []
    prefered_language: str = Field(default='Татарский язык')

class Task(BaseModel):
  task_text: str = Field(description='Создай предложение на данную тебе тему на татарском языке с пропущенным словом, длина полученной строки не больше 40 символов.', max_length=40)
  task_answer1: str = Field(description='Это первый вариант ответа', max_lenght=20)
  task_answer2: str = Field(description='Это второй вариант ответа', max_lenght=20)
  task_answer3: str = Field(description='Это третий вариант ответа', max_lenght=20)
  task_answer4: str = Field(description='Это четвертый вариант ответа', max_lenght=20)
  right_answer: str = Field(description='Здесь Напиши правильный вариант ответа', max_lenght=20)

class Storypoint(BaseModel):
    description: str
    theme:str

class StorySecond(BaseModel):
    storypoints: list[Storypoint] = []

class Quest(BaseModel):
  description: str
  theme:str
  tasks: list[Task]=[]
  replika:Optional[str]
  main_npc:ConceptNPC

class Story(BaseModel):
  npcs:list[ConceptNPC]=[]
  full_description:str
  quests: list[Quest]=[]
  themes: list[str]=[]

def generate_npcs(state:ConceptFields):
  npcs = state.npcs_list
  new_npcs = []
  for npc in npcs:
    npc_dict = npc.dict()
    npc_dict['image_url'] = image_generate(f"picture of character of the child story based on his look description:{npc_dict['look_description']}")
    npc_obj = ConceptNPC.parse_obj(npc_dict)
    new_npcs.append(npc_obj)
  state.npcs_list = new_npcs
  return state


def generate_full_story_description(state:ConceptFields):
  themes = state.themes
  pretty_themes = ''
  for i in range(len(themes)):
    pretty_themes += f'{i}. {themes[i]} на языке {state.prefered_language}.\n'
  npcs = state.npcs_list
  pretty_npcs = ''
  for i in range(len(npcs)):
    npc_dict = npcs[i].dict()
    pretty_npcs += f"{i}. Имя - {npc_dict['name']}, Описание - {npc_dict['character_description']}\n"

  prompt_template = """
  Ты - Помощник пользователя в обучении языку:{prefered_language} через создание сказок и общение.
  Твоя задача из краткого описания того что он хочет видеть в сказке
  Написать полную сказку с описанием того что там происходит, куда герой отправляется.
  У тебя есть определенный список персонажей и ты можешь использовать в данной истории только их.
  Данная сказка направлена на вовлечение человека в изучение языка:{prefered_language}.
  Все события в истории должны быть связаны с персонажами и взаимодействии с ними.
  Эта история послужит структурой для генерации квестов и заданий.
  От тебя требуется получить историю или сказку которую уже можно читать.
  СЛЕДУЙ ИНСТРУКЦИЯМ.
  Ты можешь создать историю, события в которой связаны с изучением каких то тем.
  {pretty_themes}

  Список персонажей обязанных участвовать в истории. Вводи их в события по порядку, кто отмечен первым, тот участвует первым.
  {pretty_npcs}

  Далее будет представлено краткое описание истории которое дал пользователь.
  Краткое описание сюжета истории по которому ты должен идти: {description}

  Далее будут представлены дополнительные требования к истории и сюжету. Прислушивайся к ним особо внимательно.
  {additional_requirements}

  История:
  """
  story_full_description_prompt = PromptTemplate.from_template(template=prompt_template)
  chain = story_full_description_prompt | llm | StrOutputParser()
  flag = True
  counter = 0
  while flag:
    try:
      result = chain.invoke({'pretty_themes':pretty_themes, 'pretty_npcs':pretty_npcs, 'description':state.description, 'additional_requirements':state.additional_requirements, 'prefered_language':state.prefered_language})
    except Exception:
      counter += 1
      if counter >= 5:
        raise ValueError
    else:
      flag = False
  return result


def generate_story_points(state:ConceptFields, full_description:str):
  themes = state.themes
  print(themes)
  pretty_themes = ''
  for i in range(len(themes)):
    pretty_themes += f'{i}. Данная точка сюжета должна быть про изучение темы {themes[i]} на языке: {state.prefered_language}.\n'
  prompt_template = """
  Ты - Помощник пользователя в обучении татарскому языку через создание сказок и общение.
  Твоя задача из полного описания сказки создать точки сюжета по которым будет проходить пользователь.
  Обязательно следуй всем инструкциям.
  Список тем

  {pretty_themes}

  Строго соблюдай следующие инструкции:

  {format_instructions}

  ПОЖАЛУЙСТА, обратите внимание на следующие условия:

  Если у тебя есть единственная тема урока сгенерируй только одну точку сюжета где разворачивается одно событие или разговор.
  Если тебе даны несколько тем, то для каждой сгенерируй точку сюжета с описанием.
  Точки сюжета должны иметь последовательные линейные события и должны нести для пользователя сюжетный смысл.

  Например если полный сюжет истории это приключение Капитана Джека воробья, и темы это Семья, школа и времена года, то точки сюжета это поход капитана к своей семье и разговор с ними(и еще подробное описание),
  следующая точка это капитан джек воробей отправляет сына в школу и рассказывает про это, а следующая это когда он читает книгу про времена года и плывет на корабле чтобы увидеть все времена года.

  Сделай подробное их описание исходя из инструкций.
  Всего точек истории должно быть ровно столько сколько и тем.
  Верни только список описаний этих точек истории исходя из инструкций.

  Полное описание сюжета истории: {full_description}
  """
  story_points_prompt = PromptTemplate.from_template(template=prompt_template)
  class StoryPoint(BaseModel):
    description: str = Field(description='Создай описание этой точки сюжета связанного с номером темы. Она должна либо быть начальным событием истории либо следовать за предыдущим и иметь тематику темы.')

  class Storysecond(BaseModel):
    storypoints: list[StoryPoint] = []

    @validator('storypoints', allow_reuse=True)
    def lenght_equals_right(cls, v: list[StoryPoint]) -> list[StoryPoint]:
      print(v)
      if len(v)!=len(themes):
        raise ValueError('Недопустимое количество точек истории')
      return v

  story_points_output_parser = PydanticOutputParser(pydantic_object=Storysecond)
  story_points_instructions = story_points_output_parser.get_format_instructions()
  chain = story_points_prompt | llm | story_points_output_parser
  flag = True
  counter = 0
  while flag:
    try:
      result = chain.invoke({'pretty_themes':pretty_themes, 'format_instructions':story_points_instructions, 'full_description':full_description})
    except Exception:
      counter += 1
      if counter >= 5:
        raise ValueError
    else:
      flag = False
  return result

def make_task(story_point:dict, state:ConceptFields, i:int):
  prompt_template = """
  Ты - Помощник пользователя в обучении татарскому языку через создание тестовых заданий.
  Задание должно относиться к определенной теме которая будет представлена ниже

  {theme}
  Задание которое ты должен создать это предложение на языке: {prefered_language}
  длиной не более 40 символов, в котором ты специально пропустишь одно слово и отметишь это место троеточием.
  Ты также должен придумать 4 варианта ответа, слово которое нужно вставить, и один из этих вариантов верный.
  Также ты отмечаешь верный вариант.
  Строго соблюдай следующие инструкции:

  {format_instructions}

  От тебя требуется только предложение с пропущенным словом, 4 слово, и выделить правильный ответ
  """
  task_prompt = PromptTemplate.from_template(template=prompt_template)
  task_output_parser = PydanticOutputParser(pydantic_object=Task)
  task_instructions = task_output_parser.get_format_instructions()
  chain = task_prompt | llm | task_output_parser
  flag = True
  counter = 0
  while flag:
    try:
      result = chain.invoke({'theme':state.themes[i], 'format_instructions':task_instructions, 'prefered_language':state.prefered_language})
    except Exception:
      counter += 1
      if counter >= 5:
        raise ValueError
    else:
      flag = False
  return result

def generate_replika(story_point:dict, state:ConceptFields, i:int):
  prompt_template = """
  Ты - помощник пользователя в обучении языку: {prefered_language}.
  Ты находишься посреди сюжета сказки и тебе известно что в данной части.
  должно произойти какое то событие.
  У тебя есть один персонаж из нескольких в данной сказке и именно ему ты должен.
  написать реплику которую он передаст из своих уст пользователю.

  Это сообщение должно выполнять несколько условий:

  Реплика должна быть краткой и понятной. Длина реплики не должна превышать 300 символов.

  Сообщение идет от лица персонажа к пользователю.

  Сообщение должно отражать суть происходящего на данный момент в истории.
  Например, Персонаж спешит к пользователю чтобы сказать о наводнении.

  Язык на котором ты можешь доносить эту информацию может быть русском. Но в реплике обязаны быть слова из языка который указан ниже:
  {prefered_language}
  Сообщение должно провести небольшой экскурс по теме которую проходит пользователь.
  Например, отметить несколько слов с переводом на этом языке по теме семья.
  Если ты хочешь написать текст на этом языке удели особое внимание, чтобы не ошибиться.
  Тему укажу ниже.

  Сообщение должно соответствовать характеру персонажа который говорит это.

  Сообщение может быть объемным и должно подготовить пользователя к решению заданий по теме,
  при этом поведая ему кусок истории.

  Тема изучения главы:
  {theme}

  Описание персонажа:
  {character_description}

  Описание событий главы:

  {description}

  """
  replika_prompt = PromptTemplate.from_template(template=prompt_template)
  npcs = state.npcs_list
  themes = state.themes
  npc_dict = npcs[i%len(npcs)].dict()
  theme = themes[i]
  description = story_point['description']
  chain = replika_prompt | llm | StrOutputParser()
  flag = True
  counter = 0
  while flag:
    try:
      result = chain.invoke({'description':description, 'theme':theme, 'character_description':npc_dict['character_description'], "prefered_language":state.prefered_language})
    except Exception:
      counter += 1
      if counter >= 5:
        raise ValueError
    else:
      flag = False
  return result

def get_skazka(state:ConceptFields):
  #somehow get state
  state = ConceptFields.parse_obj(state)
  try:
    state = generate_npcs(state)
    full_description = generate_full_story_description(state)
    story_points = generate_story_points(state, full_description).dict()
    skazka = Story(npcs=state.npcs_list, full_description=full_description, themes = state.themes)
    for i, el in enumerate(story_points['storypoints']):
      new_el = Quest(description=el['description'],main_npc=state.npcs_list[i%len(state.npcs_list)], replika=generate_replika(el, state, i), theme=state.themes[i])
      for j in range(8):
        new_el.tasks.append(make_task(i=i, state=state, story_point=el))
      skazka.quests.append(new_el)
    return skazka.dict()
  except Exception:
    raise ValueError


def get_zazka(state:dict):
  try:
    quests_list = []
    quests = state['quests']
    for i, el in enumerate(quests):
      pretty_tasks = []
      for j, en in enumerate(el['tasks']):
        task_container = [en['task_answer1'], en['task_answer2'],en['task_answer3'], en['task_answer4']]
        answer = task_container.index(en['right_answer'])
        pretty_tasks.append({'title':en['task_text'], 'variants':task_container, 'answer':answer, 'state':0})
      quest = {
          'replika':el['replika'],
          'image_url':el['main_npc']['image_url'],
          'tasks': pretty_tasks
      }
      quests_list.append(quest)
    return quests_list
  except Exception:
    raise ValueError
  

