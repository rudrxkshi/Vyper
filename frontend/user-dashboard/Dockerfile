FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_VYPER_API_BASE_URL=/api
ENV NEXT_PUBLIC_VYPER_API_BASE_URL=$NEXT_PUBLIC_VYPER_API_BASE_URL
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY --from=build /app/out /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
USER 101
EXPOSE 8080
