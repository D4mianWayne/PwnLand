# 🔥 Welcome to PwnLand

> *"Because exploits taste better with documentation"*  
> — d4mianwayne

## 🚀 Quick Links
- [Buffer Overflow Guide](/BufferOverflows)
- [Heap Exploitation Lab](/Heap/GLIBC-2.23)
- [Latest CTF Writeups](/CTF-Writeups)

## 📌 Featured Articles
```yaml
{% raw %}{% for page in nav|selectattr("meta.featured")|list %}
- [{{ page.title }}]({{ page.url }})
{% endfor %}{% endraw %}