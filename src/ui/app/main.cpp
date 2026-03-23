#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "ui/app/MainController.h"

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    application.setOrganizationName("Pcap Flow Lab");
    application.setApplicationName("Pcap Flow Lab");

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
    return application.exec();
}
