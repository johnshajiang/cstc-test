# KonaJDK测试集

## 测试工具

- 测试执行工具：Gradle 8.10.1
- 功能测试工具：JUnit 5.10
- 性能测试工具：
  - 微基准测试工具：JMH 1.37
  - 大数据基准测试工具：HiBench 7.0

## 协程

### 测试目标

- 功能：KonaJDK 8能够创建协程，并在其中执行任务。
- 兼容性：调用KonaJDK 8的协程实现只需要使用OpenJDK 21的API。

### 功能测试

```
export JAVA_HOME=/path/to/konajdk8
gradle :konajdk8:testOnCurrent --tests "cstc.fiber.*"
```

### 兼容性测试

相同的的功能测试程序也可以在OpenJDK 21上成功编译。

```
export JAVA_HOME=/path/to/openjdk21
gradle :konafiber8:compileTestJava
```

## 国密

### 测试目标

- 功能：KonaJDK 8能够使用国密算法SM2，SM3和SM4，并能使用国密TLPC协议创建安全连接。
- 兼容性：调用KonaJDK 8的国密实现只需要使用OpenJDK的API。
- 性能：KonaJDK 8中的TLCP握手性能高于TLS握手。

### 功能测试

```
export JAVA_HOME=/path/to/konajdk8
gradle :konajdk8:testOnCurrent --tests "cstc.crypto.*"
gradle :konajdk8:testOnCurrent --tests "cstc.ssl.*"
```

### 兼容性测试

相同的的功能测试程序也可以在OpenJDK 8上成功编译。

```
export JAVA_HOME=/path/to/openjdk8
gradle :konajdk8:compileTestJava
```

### 性能测试

```
export JAVA_HOME=/path/to/konajdk8
gradle :konajdk8:jmh --args="cstc.ssl.*"
```

## UTF-8编码

### 测试目标

- 性能：KonaJDK 8的UTF-8编码与解码性能提升。

### 性能测试

当KonaJDK 8.0.7升级到8.0.20之后，UTF-8编解码的性能有提升。

```
export JAVA_HOME=/path/to/konajdk8.0.20
gradle :konajdk8:jmh --tests "cstc.utf8.*"
```

```
export JAVA_HOME=/path/to/konajdk8.0.7
gradle :konajdk8:jmh --tests "cstc.utf8.*"
```

## AOT编译

AOT编译特性的测试将使用KonaJDK 8与OpenJDK 8。该测试相对复杂，需要在特定的测试环境中执行`HiBench`测试基准，以观察到开启AOT的KonaJDK 8的性能优势。
