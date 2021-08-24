FROM openjdk:13-alpine

RUN rm -rf /app;mkdir -p /app
WORKDIR /app
ADD Helloworld.java /app

RUN javac Helloworld.java

#workaround
RUN cp /opt/openjdk-13/lib/server/libjvm.so /opt/openjdk-13/lib/

#CMD ["java", "Helloworld"]
CMD ["/bin/sh"]
