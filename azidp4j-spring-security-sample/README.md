# azidp4j-spring-security-sample

## Deploy for conformance test

### Docker Build

```
./gradlew bootBuildImage --imageName=azidp4j/spring-security-sample
```

### Push ECR

```
aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/f8x3d3l2
```

```
VERSION=v5
docker tag azidp4j/spring-security-sample:latest public.ecr.aws/f8x3d3l2/azidp4j-spring-security-sample:${VERSION}
docker push public.ecr.aws/f8x3d3l2/azidp4j-spring-security-sample:${VERSION}
```
