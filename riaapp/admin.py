from django.contrib import admin
from riaapp.models import Register,Contact,Payments,Courses,Documents,Certificate,Trainer,Attendace
# Register your models here.
admin.site.register(Register)
admin.site.register(Courses)
admin.site.register(Payments)
admin.site.register(Documents)
admin.site.register(Certificate)
admin.site.register(Contact)
admin.site.register(Trainer)
admin.site.register(Attendace)