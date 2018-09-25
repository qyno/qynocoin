#ifndef PRIVATESENDCONFIG_H
#define PRIVATESENDCONFIG_H

#include <QDialog>

namespace Ui
{
class PrivatesendConfig;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class PrivatesendConfig : public QDialog
{
    Q_OBJECT

public:
    PrivatesendConfig(QWidget* parent = 0);
    ~PrivatesendConfig();

    void setModel(WalletModel* model);


private:
    Ui::PrivatesendConfig* ui;
    WalletModel* model;
    void configure(bool enabled, int coins, int rounds);

private slots:

    void clickBasic();
    void clickHigh();
    void clickMax();
};

#endif // PRIVATESENDCONFIG_H
