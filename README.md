# Tkinter-s-UDP-SMS-machine

这是学了socket和tkinter库的小实践，我通过tkinter库构造了一个图形化界面，该界面支持两个功能，发送UDP数据包到指定位置和监听端口并接受UDP数据包，这两个独立功能分别由两个线程来实现，以保证阻滞式的监听和发送中，前台仍可以正常响应用户的操作，线程之间通过队列交互天然避免线程竞争冒险，结束段代码自动维护并终止两个线程，保证关闭优雅且安全，代码在局域网内测试正常，记得关闭windows自带的防火墙。

This is a small practice of learning socket and tkinter library. I constructed a graphical interface using tkinter library, which supports two functions: sending UDP packets to a specified location and listening to ports and receiving UDP packets. These two independent functions are implemented by two threads respectively to ensure blocking listening and sending, and the front-end can still respond to user operations normally. Threads interact naturally through queues to avoid thread competition and risks. The end of the code automatically maintains and terminates the two threads, ensuring elegant and safe shutdown. The code is tested normally in the local area network, and remember to turn off the built-in firewall of Windows.
