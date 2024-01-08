@echo off
cd services/identity
buf generate ../../definitions
cd ../gateway
buf generate ../../definitions
cd ../user
buf generate ../../definitions
cd ../..