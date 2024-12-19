from opencve.conf.base import INSTALLED_APPS, MIDDLEWARE

# Custom advancedcve apps
ADVANCEDCVE_APPS = [
    'advancedcve',
]

# Custom advancedcve middlewares
ADVANCEDCVE_MIDDLEWARE = [
]

# Combine both lists
INSTALLED_APPS += ADVANCEDCVE_APPS
MIDDLEWARE += ADVANCEDCVE_MIDDLEWARE