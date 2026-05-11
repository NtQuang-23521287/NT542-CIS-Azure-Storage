#!/usr/bin/env bash

RG="rg-hospital-cis"
SA="sthospitalcis001"

mkdir -p reports

echo "Collecting storage account..."
az storage account show \
  --name $SA \
  --resource-group $RG \
  > reports/storage.json

echo "Collecting blob properties..."
az storage account blob-service-properties show \
  --account-name $SA \
  --resource-group $RG \
  > reports/blob.json

echo "Done!"