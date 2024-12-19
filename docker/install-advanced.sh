echo "--> Cloning OpenCVE needed repositories"
docker exec -it airflow-scheduler git clone $CERT_IST_REPO /home/airflow/repositories/certist

echo "--> Importing AdvancedCVE KB inside the database, this can take 15 to 30min."
docker exec -it webserver python manage.py import_certist

echo "--> Unpausing the dag"
docker exec -it airflow-scheduler airflow dags unpause advancedcve