FROM mcr.microsoft.com/dotnet/core/aspnet:2.2-stretch-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443
EXPOSE 8080/tcp
ENV ASPNETCORE_URLS https://*:8080

FROM mcr.microsoft.com/dotnet/core/sdk:2.2-stretch AS build
WORKDIR /app

COPY *.csproj ./
RUN dotnet restore Decent.csproj

COPY . ./
RUN dotnet publish Decent.csproj -c Release -o out

FROM mcr.microsoft.com/dotnet/core/sdk:2.2-stretch AS runtime
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "Decent.dll"]
