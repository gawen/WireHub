W = wan()

M(W | peer{up_ip=subnet('51.15.227.165', 0)})   -- root

M(W | peer{up_ip=subnet("1.1.1.1", 0)})

HomeLan = W | nat{up_ip=subnet('1.1.1.2', 0)}
M(HomeLan | peer())
M(HomeLan | peer())

