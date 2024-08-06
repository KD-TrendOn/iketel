import os
from dotenv import load_dotenv

load_dotenv()

ip=os.getenv('ip')
PGUSER = str(os.getenv("PGUSER"))
PGPASSWORD = str(os.getenv("PGPASSWORD"))
DATABASE = str(os.getenv("DATABASE"))

POSTGRES_URI=f'postgresql://{PGUSER}:{PGPASSWORD}@{ip}/{DATABASE}'