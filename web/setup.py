from setuptools import find_packages, setup


# Read requirements.txt
def read_requirements():
    with open("requirements.txt") as req_file:
        return req_file.read().splitlines()
    
setup(
    name='advancedcve',                   # Name of your package
    version='0.0.1',                      # Initial release version
    packages=find_packages(),             # Automatically discover all packages
    include_package_data=False,            # Include static files and templates
    install_requires=read_requirements(), # Load dependencies from requirements.txt
)