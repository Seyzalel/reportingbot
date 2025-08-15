logging.basicConfig(level=logging.INFO)
USER = quote_plus(os.environ.get('DB_USER', 'seyzalel'))
PWD = quote_plus(os.environ.get('DB_PASS', 'Sey17zalel17@$'))
MONGO_URI = f"mongodb+srv://{USER}:{PWD}@cluster0.krrj4yp.mongodb.net/bcbravus?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['reportingbot']