# SQLinjectorDetector
A set of tools  that can detect  SQL Injection attacks  so you can block the attack and save resources they consume.

Here is the the mySQL database structure required.
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

Attacking IPs are stored in this table:
```
CREATE TABLE `tblAttIPs` (
  `attIP` varchar(50) CHARACTER SET latin1 DEFAULT NULL,
  `attDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `banned` datetime DEFAULT NULL,
  `nAtts` bigint(20) DEFAULT '0',
  `attLasthit` datetime DEFAULT NULL,
  `nBlocks` bigint(20) DEFAULT NULL,
  `IPFOstatus` int(11) DEFAULT NULL,
  KEY `ndxAttDate` (`attDate`),
  KEY `ndxBanned` (`banned`),
  KEY `ndxAttLasthit` (`attLasthit`),
  KEY `ndxAttIP` (`attIP`),
  KEY `ndxIPFOstatus` (`IPFOstatus`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

