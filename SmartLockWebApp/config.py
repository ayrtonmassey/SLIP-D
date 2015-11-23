import os

#######################################
# ======== Flask Application ======== #
#######################################

# The app's name, as displayed in page content.
APP_NAME = 'smartlock'

# The app's secret key.
SECRET_KEY = os.getenv('SECRET_KEY')

################################
# ======= SmartLock API ====== #
################################

# The domain/port of the API.
API_BASE_ADDR = 'http://slip-d-api.herokuapp.com'
# API_BASE_ADDR = 'http://localhost:5000'

# The domain of your site, e.g. www.mysite.com
DOMAIN = os.getenv('DOMAIN')
