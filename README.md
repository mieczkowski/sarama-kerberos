# sarama-kerberos
Library for kerberos authorization in Sarama library

`libsasl2-dev` is required.

Example usage:

```Go
cfg := sarama.NewConfig()
cfg.ClientID = "some-client"
cfg.Net.SASL.Enable = true
cfg.Net.SASL.Mechanism = sarama.SASLTypeCustom
cfg.Net.SASL.CustomHandler = NewSaramaKerberosSASL("myKafka", "/home/mieczkowski/kafka-auth-test.keytab", "kafka-auth-test-principal")
```
