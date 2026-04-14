#include <QApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QWindow>

#include "ui/app/MainController.h"

#ifndef PFL_APP_VERSION
#define PFL_APP_VERSION "0.0.0"
#endif

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    application.setOrganizationName("Pcap Flow Lab");
    application.setApplicationName("Pcap Flow Lab");
    application.setApplicationVersion(QStringLiteral(PFL_APP_VERSION));

    const QIcon app_icon(QStringLiteral(":/assets/icons/app.ico"));
    if (!app_icon.isNull()) {
        application.setWindowIcon(app_icon);
    }

    QQmlApplicationEngine engine {};
    pfl::MainController main_controller {};
    engine.rootContext()->setContextProperty("mainController", &main_controller);

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &application,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.loadFromModule("PcapFlowLab", "Main");

    if (!app_icon.isNull()) {
        for (QObject* object : engine.rootObjects()) {
            if (auto* window = qobject_cast<QWindow*>(object); window != nullptr) {
                window->setIcon(app_icon);
            }
        }
    }

    return application.exec();
}
