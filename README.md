# Illumio-Firewall-test

## Language used: 
Java

## Underlying Logic:
Since it was mentioned that the rules could be >=400K, I have created a csv for storing rules. I needed a structure to make the data compact and make retrieval and comparison with input packets easier, so I created a dictionary(HashMap) of dictionaries where the format would be:

{k1:{k2:value}}, here k1 = combination of possible IP addresses and port numbers, k2 = protocol, value = direction.

This makes time to compare much faster at the cost of space. This was a tradeoff. But I feel that would be worth, since in today's world, memory is cheaper and time is more expensive.

For generating the IP addresses within the given value range, I faced some problems but I figured that I can generate IP addresses just like generating binary numbers between a range but with a base of 256. Generating port numbers was relatively straightforward.
There were essentially 4 cases:
1. When both IP Address and port are singular values.
2. When either one of them is range (2 separate cases).
3. When both are ranges given.
Based on this I created the combinations and stored them as k1 in the hashmap.

k2 had only 2 possible values {tcp,udp} and so did 'value' {inbound, outbound}.

## Features handled:
1. Object oriented principles 
2. Encapsulation - The code is encapsulated at appropriate places. The Hashmap is made private because a user should not have open access to the firewall rules storage and be able to change it.
Although, there is code duplication in the constructor of my class fireWall, involving generating the IP Addresses and ports from the given ranges. I wanted to put the logic in a method but calling a method from inside a constructor is not advisable since it happens before object creation and may lead to corrupted code.
3. I have added sufficient comments in the code to aid a user in understanding the logic/variables.


## Issues encountered while testing: 
1. With an IP range of 0.0.0.0-255.255.255.255, there is an OutOfMemoryError: Java Heap Exception.
2. generating a wider range of test cases.

## If I had more than 90 minutes:
1. I would try other data structure combinations using hashkeys as a combination of IP+Port with the value as a list of potential combinations of protocol and direction for better retrieval.
2. Try out more test cases and edge cases by generating a large input csv file and comparing performance.
3. Improve the encapsulation and reduce code duplication.
4. Better documentation

## Team preference ranking
1. Policy
2. Data
3. Platform
