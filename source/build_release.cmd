@echo off
setlocal

rem Windows AOT build (native ahead-of-time)
dotnet publish Astral-PE.csproj -c Release -o build_x64 /p:TargetFramework=net9.0 /p:PublishAot=true /p:InvariantGlobalization=true /p:ImplicitUsings=enable /p:Nullable=enable /p:EnableUnsafeBinaryFormatterSerialization=false /p:TrimmerUnreferencedCodeAnalyzerEnabled=true /p:HttpActivityPropagationSupport=false /p:EnableUnsafeUTF7Encoding=false /p:ProduceReferenceAssembly=false /p:MetadataUpdaterSupport=false /p:UseSystemResourceKeys=true /p:UseNativeHttpHandler=true /p:TrimmerRemoveSymbols=true /p:EventSourceSupport=false /p:EnableTrimAnalyzer=true /p:StackTraceSupport=false /p:TrimmerSingleWarn=false /p:DebuggerSupport=false /p:DebugSymbols=false /p:DebugType=none /p:TrimMode=link /p:Optimize=true

rem Linux self-contained build
dotnet publish Astral-PE.csproj -r linux-x64 -c Release -o build_x64 --self-contained true /p:TargetFramework=net9.0 /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=false /p:PublishTrimmed=true /p:TrimMode=link /p:Nullable=enable /p:Optimize=true /p:DebugType=none /p:DebugSymbols=false /p:ProduceReferenceAssembly=false /p:UseNativeHttpHandler=true

endlocal