FROM openjdk:13-alpine

RUN rm -rf /app;mkdir -p /app
WORKDIR /app
ADD helloworld.java /app

RUN javac helloworld.java

#workaround
RUN cp /opt/openjdk-13/lib/server/libjvm.so /opt/openjdk-13/lib/

#CMD ["java", "helloworld"]
CMD ["/bin/sh"]
