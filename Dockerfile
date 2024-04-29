FROM mcr.microsoft.com/dotnet/aspnet:8.0

RUN mkdir /prover-files

WORKDIR /app
EXPOSE 80
EXPOSE 443
EXPOSE 11111
EXPOSE 30000

COPY bin/Release/net8.0/publish/ /app/

ENV ASPNETCORE_URLS=http://0.0.0.0:7020

ENTRYPOINT ["dotnet", "ProofService.dll"]