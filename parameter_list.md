#参数列表的作用

# Introduction #

解释文本文件GoogleTest.properties中各个参数的作用


# Details #

  * urls：测试中所使用的URL列表，用空格分隔。
  * interval：测试间隔（秒），2次测试中的时间间隔，1次测试为一个确定的URL的一起请求。比如urls有2个，interval为10，那么每20秒循环测试urls中的URL列表。
  * times：测试次数，urls中的每个URL都测试times次数。比如urls中有2个URL，interval为5，times为10，那么总测试时间为2\*5\*10=100秒。
  * log：生成的log文件。