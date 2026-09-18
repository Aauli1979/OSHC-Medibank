* For running the web-app, need to run the backend and frontend separately (Powershell/cmd), for running the backend need to allocate a port:

* Commands to allocate a port and run the backend:
  netstat -ano | findstr :8080 ==> tasklist /FI "PID eq 8840" ==> taskkill /PID 8840 /F ==> mvn spring-boot:run (for running the 1st time)

* If already ran the backend and need to run again ==> mvn spring-boot:run (after the 1st time)
************************************************************************************************************
* Commands to run the Frontend ==> npm install ==> npm run dev 

* If the frontend has error ==> run npm clean package ==> npm install ==> npm run dev
