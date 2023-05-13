# Web指纹识别

利用requests库对目标网站进行访问，利用指纹库与response的字段进行对比，分析网站的类型

指纹库采用[Finger](https://github.com/EASY233/Finger)的指纹库
# Todo
- [ ] 利用chromedriver来进行网站访问，可以获得更多的指纹信息
- [ ] 收集更为强大的指纹库，实现正则表达式匹配指纹
- [ ] 将favicon的hash生成与quake的favicon字段生成规则一致
# 依赖

```text
lxml==4.9.2
mmh3==3.1.0
requests==2.24.0
urllib3==1.25.11
```

# 参考

* [Finger](https://www.baidu.com/)
* [Ehole](https://github.com/EdgeSecurityTeam/EHole)
