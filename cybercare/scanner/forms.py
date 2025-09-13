from django import forms

class ScanForm(forms.Form):
    target = forms.CharField(label="Domeniu sau IP", max_length=255)


class ScanForm(forms.Form):
    target = forms.CharField(
        label="Target",
        widget=forms.TextInput(attrs={"class": "form-control"})
    )
