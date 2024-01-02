# SQLinjectorDetector
A set of tools  that can detect  SQL Injection attacks  so you can block the attack and save resources they consume.

Here is the the mkySQL database structure required.
```
CREATE TABLE `tblStrangeStuf` (
  `stsMd5` varchar(50) CHARACTER SET latin1 DEFAULT NULL,
  `stsClean` longtext CHARACTER SET latin1,
  `stsLook` int(11) DEFAULT NULL,
  `stsDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `stsThreat` decimal(12,9) DEFAULT NULL,
  KEY `ndxStsMd5` (`stsMd5`),
  KEY `ndxStsLook` (`stsLook`),
  KEY `ndxStsDate` (`stsDate`),
  KEY `ndxStsThreat` (`stsThreat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```
You can get a copy of the current data for the database here:
https://www.bitmonky.com/strangeStuff.json

It contains  37,686 confirmed attack strings and  13,197  unconfirmed (possible attacks)

