FROM node:latest AS build
RUN npm ci
FROM node:latest
COPY --from=build /app /app
