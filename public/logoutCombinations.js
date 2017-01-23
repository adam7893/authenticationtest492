var arr = ["expressLogout", "expressLogOut"]

function createButtons() {
    var buttonGroup = document.getElementById("button group");

    arr.forEach(function(ele) {
        var container = document.createElement("a");
        var button = document.createElement("BUTTON");

        button.id = "test";
        button.innerHTML = ele;

        container.href = ele;

        container.appendChild(button);
        buttonGroup.appendChild(container);
    });
}

/*
    req.session.destroy()
    req.logout()
    res.redirect()
        redirect o IdP logoutURL?
    res.clearCookie('connect.sid')


 */