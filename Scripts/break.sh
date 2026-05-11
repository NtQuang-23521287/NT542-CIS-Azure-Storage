#!/usr/bin/env bash

RG="rg-hospital-cis"
SA="sthospitalcis001"

echo "Turning ON public access (bad config)..."

az storage account update \
  --name $SA \
  --resource-group $RG \
  --allow-blob-public-access true